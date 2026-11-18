//! A submission session that signed in before its account was disabled, or
//! before its credentials were reset, gets `421` and a close at its next
//! command, and a message whose body was in flight is not delivered.
//! Another account's change leaves it alone.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::client::TlsStream;

use super::tests_auth::{connector, reply};
use super::*;
use crate::directory_store::AccountStore;
use crate::smtp::sink::MemorySink;
use crate::test_support::{accounts, fixtures};

const WITHDRAWN: &str = "421 4.7.0 account no longer available\r\n";

type Client = TlsStream<tokio::io::DuplexStream>;

/// A server on the store's directory handle, and alice signed in to it.
async fn signed_in(
	store: &AccountStore,
	sink: Arc<MemorySink>,
) -> (Client, tokio::task::JoinHandle<std::io::Result<()>>) {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_directory(store.handle())
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
	let mut ehlo = String::new();
	while !ehlo.contains("250 ") {
		ehlo.push_str(&reply(&mut tls).await);
	}
	let plain = B64.encode(format!("\0alice\0{}", fixtures::password()));
	tls.write_all(format!("AUTH PLAIN {plain}\r\n").as_bytes())
		.await
		.expect("auth");
	let auth = reply(&mut tls).await;
	assert!(auth.starts_with("235 "), "{auth}");
	(tls, task)
}

/// The next reply, then whether the server closed after it.
async fn closing_reply(tls: &mut Client) -> (String, bool) {
	let first = reply(tls).await;
	let mut chunk = [0u8; 16];
	let closed = first == WITHDRAWN && matches!(tls.read(&mut chunk).await, Ok(0) | Err(_));
	(first, closed)
}

#[tokio::test]
async fn a_command_after_the_account_is_disabled_gets_421_and_a_close() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let (mut tls, task) = signed_in(&store, Arc::new(MemorySink::new())).await;
	accounts::disable(&store, "alice");
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\n")
		.await
		.expect("mail");
	assert_eq!(closing_reply(&mut tls).await, (WITHDRAWN.to_string(), true));
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn a_command_after_a_credential_reset_gets_421_and_a_close() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let (mut tls, task) = signed_in(&store, Arc::new(MemorySink::new())).await;
	accounts::reset(&store, "alice");
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\n")
		.await
		.expect("mail");
	assert_eq!(closing_reply(&mut tls).await, (WITHDRAWN.to_string(), true));
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn a_body_in_flight_when_the_account_is_disabled_is_not_delivered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let sink = Arc::new(MemorySink::new());
	let (mut tls, task) = signed_in(&store, Arc::clone(&sink)).await;
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\n")
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut tls).await);
	}
	tls.write_all(b"From: alice@example.org\r\nSubject: late\r\n\r\nbody\r\n")
		.await
		.expect("body");
	accounts::disable(&store, "alice");
	tls.write_all(b".\r\n").await.expect("dot");
	assert_eq!(closing_reply(&mut tls).await, (WITHDRAWN.to_string(), true));
	assert!(task.await.expect("join").is_ok());
	assert!(sink.messages().is_empty(), "the message was delivered");
}

#[tokio::test]
async fn disabling_another_account_leaves_the_session_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let (mut tls, task) = signed_in(&store, Arc::new(MemorySink::new())).await;
	accounts::disable(&store, "bob");
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\n")
		.await
		.expect("mail");
	let (mail, closed) = closing_reply(&mut tls).await;
	assert!(mail.starts_with("250 "), "{mail}");
	assert!(!closed);
	task.abort();
}
