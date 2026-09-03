//! AUTH over a STARTTLS-upgraded SMTP connection (the CollectAuthResponse loop).

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

fn directory_with_password() -> DirectoryHandle {
	DirectoryHandle::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash(crate::smtp::auth::tests::fixture_password()),
		)])),
	)
}

fn connector(
	cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> tokio_rustls::TlsConnector {
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
	let mut buffer = [0u8; 1024];
	let read = reader.read(&mut buffer).await.expect("read");
	String::from_utf8_lossy(&buffer[..read]).to_string()
}

#[tokio::test]
async fn auth_login_over_starttls_authenticates() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory_with_password())
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Opportunistic,
		);

	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut client).await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(reply(&mut client).await.starts_with("220 "));

	let server_name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector(cert)
		.connect(server_name, client)
		.await
		.expect("handshake");
	assert!(reply(&mut tls).await.starts_with("220 "));
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let ehlo = reply(&mut tls).await;
	assert!(ehlo.contains("AUTH"), "{ehlo}");

	// AUTH LOGIN exchanges username then password over the wire.
	tls.write_all(b"AUTH LOGIN\r\n").await.expect("auth");
	assert!(reply(&mut tls).await.starts_with("334 "));
	let password = crate::smtp::auth::tests::fixture_password().to_string();
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode(&password)).as_bytes())
		.await
		.expect("pass");
	assert!(
		reply(&mut tls).await.starts_with("235 "),
		"auth should succeed"
	);

	drop(tls);
	task.abort();
}

/// An authenticated submission that lacks both `Message-ID` and `Date` is
/// stamped with both before the message lands in the sink. The `Message-ID`
/// is shaped `<uuid@domain>` with the reverse-path's domain; the `Date` is
/// the RFC 5322 form of `now`. They land at the top of the header block,
/// ahead of the client's `Subject:`.
#[tokio::test]
async fn an_authenticated_submission_without_message_id_gets_one() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory_with_password())
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Opportunistic,
		);

	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut client).await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(reply(&mut client).await.starts_with("220 "));

	let server_name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector(cert)
		.connect(server_name, client)
		.await
		.expect("handshake");
	assert!(reply(&mut tls).await.starts_with("220 "));
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut tls).await;

	// AUTH LOGIN with the minted password.
	tls.write_all(b"AUTH LOGIN\r\n").await.expect("auth");
	assert!(reply(&mut tls).await.starts_with("334 "));
	let password = crate::smtp::auth::tests::fixture_password().to_string();
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode(&password)).as_bytes())
		.await
		.expect("pass");
	assert!(
		reply(&mut tls).await.starts_with("235 "),
		"auth should succeed"
	);

	// Now submit a message with no Message-ID and no Date.
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@elsewhere.example>\r\nDATA\r\n")
		.await
		.expect("mail/rcpt/data");
	assert!(
		reply(&mut tls).await.starts_with("250 "),
		"MAIL FROM accepted"
	);
	assert!(
		reply(&mut tls).await.starts_with("250 "),
		"RCPT TO accepted"
	);
	assert!(reply(&mut tls).await.starts_with("354 "), "DATA go-ahead");
	tls.write_all(b"Subject: no id and no date\r\n\r\nbody\r\n.\r\nQUIT\r\n")
		.await
		.expect("data");
	let mut tail = String::new();
	while !tail.contains("221 ") {
		tail.push_str(&reply(&mut tls).await);
	}

	drop(tls);
	task.await.expect("server task").expect("server result");

	let messages = sink.messages();
	assert_eq!(messages.len(), 1, "exactly one delivered message");
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
	// The Received trace header sits outermost; the stamper's lines come
	// right after it (before the client's own headers).
	let message_id_line = data
		.lines()
		.find(|line| line.starts_with("Message-ID:"))
		.expect("stamped Message-ID present");
	let angle = message_id_line
		.find('<')
		.zip(message_id_line.find('>'))
		.expect("angle brackets around id");
	let id_inner = &message_id_line[angle.0 + 1..angle.1];
	let (_, domain) = id_inner.split_once('@').expect("local@domain");
	assert_eq!(domain, "example.org", "id is under the reverse-path domain");
	// Date is the RFC 5322 form of `now`.
	let date_line = data
		.lines()
		.find(|line| line.starts_with("Date:"))
		.expect("stamped Date present");
	let date_value = date_line.trim_start_matches("Date: ").trim();
	// 2026-09-03 is a Thursday; the test is timezone-agnostic (UTC).
	assert!(
		date_value.ends_with("+0000"),
		"Date must end with +0000 (UTC): {date_value}"
	);
	// Both stamps precede the client's own Subject: line.
	let subject_idx = data.find("Subject: ").expect("subject line");
	let message_id_idx = data.find("Message-ID: ").expect("message-id");
	let date_idx = data.find("Date: ").expect("date");
	assert!(
		message_id_idx < subject_idx && date_idx < subject_idx,
		"stamps before Subject: {data}"
	);
}

/// An unauthenticated inbound message is not stamped: the server never
/// rewrites a relay's headers, only authenticated submissions. The
/// `Received:` trace is prepended but `Message-ID` and `Date` are left as
/// the sending server supplied them.
#[tokio::test]
async fn an_unauthenticated_inbound_message_is_not_stamped() {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory_with_password());

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let (mut client_read, mut client_write) = tokio::io::split(client);
	let script = b"EHLO c.example.org\r\n\
MAIL FROM:<relay@elsewhere.example>\r\n\
RCPT TO:<alice@example.org>\r\n\
DATA\r\n\
Subject: bare relay\r\n\
\r\n\
body\r\n\
.\r\n\
QUIT\r\n";
	client_write.write_all(script).await.expect("client write");
	client_write.shutdown().await.expect("client shutdown");

	let mut output = Vec::new();
	client_read
		.read_to_end(&mut output)
		.await
		.expect("client read");
	task.await.expect("server task").expect("server result");

	let output = String::from_utf8(output).expect("ascii output");
	assert!(
		output.contains("250 "),
		"MAIL FROM and RCPT TO accepted: {output}"
	);
	assert!(
		output.ends_with("221 2.0.0 closing connection\r\n"),
		"{output}"
	);

	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
	// The server only adds a Received trace header. No Message-ID, no Date.
	let message_id_count = data
		.lines()
		.filter(|line| line.starts_with("Message-ID:"))
		.count();
	let date_count = data
		.lines()
		.filter(|line| line.starts_with("Date:"))
		.count();
	assert_eq!(message_id_count, 0, "no Message-ID stamped: {data}");
	assert_eq!(date_count, 0, "no Date stamped: {data}");
	// The client's own headers are still there.
	assert!(data.contains("Subject: bare relay"));
}

#[tokio::test(start_paused = true)]
async fn command_timeout_closes_connection() {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_directory(directory_with_password());
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	// Read the greeting, then send nothing: the command timeout (paused clock)
	// fires and the server closes the connection.
	assert!(reply(&mut client).await.starts_with("220 "));
	let mut chunk = [0u8; 16];
	assert_eq!(client.read(&mut chunk).await.expect("read"), 0);
	task.await.expect("join").expect("server result");
}
