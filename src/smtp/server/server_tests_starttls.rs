//! STARTTLS state tests (RFC 3207 section 4.2): nothing the client
//! pipelined behind STARTTLS survives the handshake, and the server does
//! not speak first inside TLS.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	))
}

fn starttls_server() -> (
	Server,
	Arc<MemorySink>,
	tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory())
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Opportunistic,
		);
	(server, sink, cert)
}

/// Read until the buffer ends with a complete final reply line
/// (`ddd text\r\n`), returning everything read.
async fn read_final<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
	let mut got = String::new();
	let mut buffer = [0u8; 1024];
	loop {
		let read = reader.read(&mut buffer).await.expect("read reply");
		assert!(read > 0, "connection closed after {got:?}");
		got.push_str(&String::from_utf8_lossy(&buffer[..read]));
		let last = got
			.trim_end_matches("\r\n")
			.rsplit("\r\n")
			.next()
			.unwrap_or("");
		if got.ends_with("\r\n") && last.as_bytes().get(3) != Some(&b'-') {
			return got;
		}
	}
}

#[tokio::test]
async fn commands_pipelined_behind_starttls_are_discarded() {
	let (server, sink, cert) = starttls_server();
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	assert!(read_final(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	assert!(read_final(&mut client).await.contains("250 STARTTLS"));

	// One write: STARTTLS plus a transaction start and a NOOP the server
	// must never act on, in plaintext or inside TLS.
	client
		.write_all(b"STARTTLS\r\nMAIL FROM:<alice@example.org>\r\nNOOP\r\n")
		.await
		.expect("starttls with injected commands");
	let plaintext = read_final(&mut client).await;
	assert_eq!(
		plaintext.matches("\r\n").count(),
		1,
		"only the STARTTLS reply travels in plaintext: {plaintext:?}"
	);
	assert!(plaintext.starts_with("220 "), "{plaintext:?}");

	let connector = super::tests::test_connector(cert);
	let name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
		.expect("server name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("tls ehlo");
	let ehlo = read_final(&mut tls).await;
	assert!(
		ehlo.starts_with("250-mail.example.org\r\n"),
		"the first bytes inside TLS answer the client's EHLO: {ehlo:?}"
	);
	assert!(!ehlo.contains("STARTTLS"), "{ehlo:?}");

	// The injected MAIL FROM opened no transaction.
	tls.write_all(b"RCPT TO:<bob@example.org>\r\n")
		.await
		.expect("rcpt");
	let rcpt = read_final(&mut tls).await;
	assert!(rcpt.starts_with("503 "), "{rcpt:?}");

	tls.write_all(b"QUIT\r\n").await.expect("quit");
	assert!(read_final(&mut tls).await.starts_with("221 "));
	drop(tls);
	task.abort();
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn own_outbound_client_delivers_over_starttls() {
	let (server, sink, _cert) = starttls_server();
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut tls = None;
	let result = crate::queue::client::deliver(
		client,
		"mail.example.org",
		"client.example.net",
		"alice@example.org",
		&["bob@example.org".to_string()],
		b"Subject: over tls\r\n\r\nbody\r\n",
		false,
		None,
		&[],
		crate::config::OutboundTls::Opportunistic,
		&mut tls,
	)
	.await;
	task.abort();
	assert_eq!(result, Ok(()));
	assert_eq!(tls, Some(crate::queue::tls_outcome::TlsOutcome::Success));
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
	assert!(data.contains("with ESMTPS;"), "{data}");
}
