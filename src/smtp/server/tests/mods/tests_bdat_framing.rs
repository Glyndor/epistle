//! A BDAT chunk that breaks the line framing ends the connection, and what
//! the client sent behind it in the same write is never run as commands.

use super::tests_data_rate::{Client, OPEN, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

fn server() -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory());
	(Arc::new(server), sink)
}

/// Send `chunk` as one LAST chunk with commands chained behind it in the
/// same write; the connection must end at the 554 with nothing stored.
async fn assert_closed_at_the_chunk(chunk: &[u8]) {
	let (server, sink) = server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	let mut write = format!("BDAT {} LAST\r\n", chunk.len()).into_bytes();
	write.extend_from_slice(chunk);
	write.extend_from_slice(b"MAIL FROM:<x@example.net>\r\nQUIT\r\n");
	client.send(&write).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "554"],
		"nothing runs after the chunk: {output:?}"
	);
	assert!(sink.messages().is_empty(), "nothing is delivered");
}

#[tokio::test(start_paused = true)]
async fn a_bare_lf_in_a_chunk_ends_the_connection_before_the_next_command() {
	assert_closed_at_the_chunk(b"Subject: hi\n\r\nhello\r\n").await;
}

#[tokio::test(start_paused = true)]
async fn a_forged_end_of_data_in_a_chunk_ends_the_connection_before_the_next_command() {
	assert_closed_at_the_chunk(b"Subject: hi\r\n\r\nx\n.\r\nQUIT\r\n").await;
}

#[tokio::test(start_paused = true)]
async fn a_nul_in_a_chunk_ends_the_connection_before_the_next_command() {
	assert_closed_at_the_chunk(b"Subject: hi\r\n\r\nx\0y\r\n").await;
}
