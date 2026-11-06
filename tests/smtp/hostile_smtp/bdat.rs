//! Hostile clients against BDAT (RFC 3030 CHUNKING) over loopback TCP: malformed sizes,
//! a size that no message can have, and commands chained behind a chunk that must stay
//! commands and never become part of the message.

use super::harness::*;

async fn session() -> (Harness, tokio::net::TcpStream) {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	ehlo(&mut client).await;
	envelope(&mut client).await;
	(server, client)
}

#[tokio::test]
async fn a_malformed_size_gets_501_and_the_session_goes_on() {
	if !super::enabled() {
		return;
	}
	for case in [
		&b"BDAT\r\n"[..],
		b"BDAT x\r\n",
		b"BDAT -1\r\n",
		b"BDAT 99999999999999999999\r\n",
		b"BDAT 5 LAST extra\r\n",
	] {
		let (server, mut client) = session().await;
		send(&mut client, case).await;
		expect(&mut client, BAD_ARGS).await;
		send(&mut client, b"NOOP\r\n").await;
		expect(&mut client, OK).await;
		assert!(server.sink.messages().is_empty());
		quit(&mut client).await;
		server.healthy().await;
	}
}

#[tokio::test]
async fn a_size_no_message_can_have_gets_552_and_the_connection_closes() {
	if !super::enabled() {
		return;
	}
	let (server, mut client) = session().await;
	send(&mut client, b"BDAT 4294967296\r\n").await;
	expect(&mut client, "552 5.3.4 message exceeds maximum size\r\n").await;
	closed(&mut client).await;
	assert!(server.sink.messages().is_empty());
	server.healthy().await;
}

#[tokio::test]
async fn commands_chained_behind_a_chunk_stay_commands_and_never_enter_the_message() {
	if !super::enabled() {
		return;
	}
	let (server, mut client) = session().await;
	send(
		&mut client,
		b"BDAT 5\r\nhelloMAIL FROM:<forged@remote.test>\r\nRCPT TO:<forged@epistle.test>\r\n",
	)
	.await;
	expect(&mut client, "250 2.0.0 chunk received\r\n").await;
	let bad_sequence = "503 5.5.1 bad sequence of commands\r\n";
	expect(&mut client, bad_sequence).await;
	expect(&mut client, bad_sequence).await;
	send(&mut client, b"BDAT 3 LAST\r\nabcQUIT\r\n").await;
	expect(&mut client, OK).await;
	expect(&mut client, "221 2.0.0 closing connection\r\n").await;
	closed(&mut client).await;
	let delivered = server.sink.messages();
	assert_eq!(
		delivered.len(),
		1,
		"one message, not one per chained command"
	);
	// The server puts its own Received line in front; what follows is exactly the two chunks.
	assert!(delivered[0].data.ends_with(b"helloabc"));
	let text = String::from_utf8_lossy(&delivered[0].data);
	assert!(
		!text.contains("forged"),
		"a chained command leaked into the message: {text}"
	);
	assert_eq!(delivered[0].reverse_path, "sender@remote.test");
	assert_eq!(delivered[0].recipients, ["tester@epistle.test"]);
	server.healthy().await;
}
