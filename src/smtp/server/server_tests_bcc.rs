//! An authenticated submission leaves without its Bcc header: the server,
//! acting as the MSA, strips it, and the Bcc recipients stay on the
//! envelope only.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::AsyncWriteExt;

use super::tests_auth::{connector, directory_with_password, reply};
use super::*;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MemorySink;

/// Submit `data` as alice over STARTTLS and AUTH LOGIN to `rcpts`; what
/// reached the sink.
async fn submit(rcpts: &[&str], data: &[u8]) -> Vec<AcceptedMessage> {
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
	let name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector(cert)
		.connect(name, client)
		.await
		.expect("handshake");
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut tls).await;
	tls.write_all(b"AUTH LOGIN\r\n").await.expect("auth");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	assert!(reply(&mut tls).await.starts_with("334 "));
	let password = crate::smtp::auth::tests::fixture_password().to_string();
	tls.write_all(format!("{}\r\n", B64.encode(&password)).as_bytes())
		.await
		.expect("pass");
	assert!(reply(&mut tls).await.starts_with("235 "), "auth");
	let mut envelope = String::from("MAIL FROM:<alice@example.org>\r\n");
	for rcpt in rcpts {
		envelope.push_str(&format!("RCPT TO:<{rcpt}>\r\n"));
	}
	envelope.push_str("DATA\r\n");
	tls.write_all(envelope.as_bytes()).await.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut tls).await);
	}
	tls.write_all(data).await.expect("data");
	tls.write_all(b".\r\nQUIT\r\n").await.expect("end");
	let mut tail = String::new();
	while !tail.contains("221 ") {
		tail.push_str(&reply(&mut tls).await);
	}
	drop(tls);
	task.await.expect("server task").expect("server result");
	sink.messages()
}

/// The header block of `data`, lowercased.
fn headers(data: &[u8]) -> String {
	let text = String::from_utf8_lossy(data).to_ascii_lowercase();
	text.split("\r\n\r\n")
		.next()
		.unwrap_or_default()
		.to_string()
}

#[tokio::test]
async fn an_authenticated_submission_loses_its_bcc_header() {
	let messages = submit(
		&["bob@elsewhere.example", "hidden@elsewhere.example"],
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\n\
		  Bcc: hidden@elsewhere.example,\r\n other@elsewhere.example\r\n\
		  Subject: s\r\n\r\nBcc: a body line stays\r\n",
	)
	.await;
	assert_eq!(messages.len(), 1);
	let message = &messages[0];
	assert_eq!(
		message.recipients,
		["bob@elsewhere.example", "hidden@elsewhere.example"],
		"the Bcc recipient stays on the envelope"
	);
	let block = headers(&message.data);
	assert!(!block.contains("\nbcc:"), "no Bcc header: {block}");
	assert!(
		!block.contains("hidden@") && !block.contains("other@"),
		"{block}"
	);
	assert!(
		String::from_utf8_lossy(&message.data).contains("\r\n\r\nBcc: a body line stays\r\n"),
		"the body is untouched"
	);
}
