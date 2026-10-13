//! Final delivery over SMTP: the stored copy of inbound mail starts with
//! the `Return-Path` the envelope gave, not one the message carried.

use tokio::io::AsyncWriteExt;

use super::tests_auth::{directory_with_password, reply};
use super::*;

/// Deliver `data` from an unauthenticated client to alice; the copies that
/// landed in her inbox.
pub(super) async fn deliver_inbound(data: &str) -> Vec<String> {
	let dir = tempfile::tempdir().expect("tempdir");
	let split =
		crate::storage::SplitDelivery::new(dir.path(), directory_with_password()).expect("sink");
	let server = Server::new("mail.example.org", Arc::new(split) as Arc<dyn MessageSink>)
		.with_directory(directory_with_password());
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(
			b"EHLO c.example.net\r\nMAIL FROM:<x@example.net>\r\nRCPT TO:<alice@example.org>\r\nDATA\r\n",
		)
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut client).await);
	}
	client
		.write_all(format!("{data}.\r\n").as_bytes())
		.await
		.expect("data");
	let answer = reply(&mut client).await;
	assert!(answer.starts_with("250 "), "{answer}");
	client.write_all(b"QUIT\r\n").await.expect("quit");
	let _ = reply(&mut client).await;
	drop(client);
	task.await.expect("server task").expect("server result");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::read_dir(inbox)
		.expect("inbox")
		.flatten()
		.filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
		.map(|entry| String::from_utf8(std::fs::read(entry.path()).expect("read")).expect("utf8"))
		.collect()
}

#[tokio::test]
async fn inbound_mail_is_stored_with_the_envelope_return_path_first() {
	let copies =
		deliver_inbound("Return-Path: <forged@attacker.example>\r\nSubject: hi\r\n\r\nbody\r\n")
			.await;
	assert_eq!(copies.len(), 1);
	assert!(
		copies[0].starts_with("Return-Path: <x@example.net>\r\nReceived: "),
		"{}",
		copies[0]
	);
	assert!(!copies[0].contains("forged@"), "{}", copies[0]);
}
