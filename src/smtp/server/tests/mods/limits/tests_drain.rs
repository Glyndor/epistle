//! A drain lets an open SMTP transaction finish, then says `421`; a session
//! with no transaction open gets the `421` at once.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;
use crate::shutdown::Drain;
use crate::smtp::sink::MemorySink;

/// Start a server session on an in-memory stream, wired to `drain`.
fn start(
	drain: &Arc<Drain>,
) -> (
	BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
	tokio::io::WriteHalf<tokio::io::DuplexStream>,
	Arc<MemorySink>,
) {
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory)
		.with_drain(Arc::clone(drain));
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	tokio::spawn(async move { server.handle(server_stream, None).await });
	let (read, write) = tokio::io::split(client);
	(BufReader::new(read), write, sink)
}

/// Read reply lines until one starts with `code` followed by a space.
async fn reply(
	reader: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
	code: &str,
) -> String {
	let mut seen = String::new();
	loop {
		let mut line = String::new();
		let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
			.await
			.unwrap_or_else(|_| panic!("no {code} reply within 5 s; got {seen:?}"))
			.expect("read");
		assert!(read > 0, "closed before a {code} reply; got {seen:?}");
		seen.push_str(&line);
		if line.starts_with(&format!("{code} ")) {
			return line;
		}
	}
}

#[tokio::test]
async fn a_transaction_in_data_finishes_before_the_goodbye() {
	let drain = Drain::new();
	let (mut reader, mut writer, sink) = start(&drain);
	reply(&mut reader, "220").await;
	for (command, code) in [
		("EHLO client.example.org\r\n", "250"),
		("MAIL FROM:<alice@example.net>\r\n", "250"),
		("RCPT TO:<bob@example.org>\r\n", "250"),
		("DATA\r\n", "354"),
	] {
		writer.write_all(command.as_bytes()).await.unwrap();
		reply(&mut reader, code).await;
	}
	drain.begin();
	tokio::time::sleep(Duration::from_millis(50)).await;
	writer
		.write_all(b"Subject: drain\r\n\r\nbody\r\n.\r\n")
		.await
		.unwrap();
	let accepted = reply(&mut reader, "250").await;
	assert!(
		accepted.contains("queued") || accepted.starts_with("250 "),
		"{accepted}"
	);
	let goodbye = reply(&mut reader, "421").await;
	assert!(goodbye.contains("4.3.2"), "{goodbye}");
	assert_eq!(
		sink.messages().len(),
		1,
		"the message was stored before the goodbye"
	);
}

#[tokio::test]
async fn an_idle_session_gets_421_when_the_drain_starts() {
	let drain = Drain::new();
	let (mut reader, mut writer, _) = start(&drain);
	reply(&mut reader, "220").await;
	writer
		.write_all(b"EHLO client.example.org\r\n")
		.await
		.unwrap();
	reply(&mut reader, "250").await;
	drain.begin();
	reply(&mut reader, "421").await;
}
