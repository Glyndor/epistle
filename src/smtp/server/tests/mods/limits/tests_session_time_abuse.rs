//! Ways a client could try to stretch its session past the lifetime: an
//! open transaction that never reaches DATA, and a body that ends past the
//! deadline followed by another message. Every test runs on tokio's paused
//! clock.

use std::time::Duration;

use tokio::time::Instant;

use super::super::rate::tests_data_rate::{
	Client, FLOOR, OPEN, body, pass, reply_codes, test_directory,
};
use super::*;
use crate::smtp::sink::MemorySink;

/// The line a session past its lifetime is closed with.
const TIME_UP: &str = "421 4.4.2 session time limit reached\r\n";

fn server_living(lifetime: Duration) -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_max_session_time(lifetime);
	(Arc::new(server), sink)
}

#[tokio::test(start_paused = true)]
async fn a_transaction_that_never_reaches_data_is_cut_on_time() {
	// MAIL and RCPT open a transaction, and one more RCPT every 250 s keeps
	// the idle timeout away without a single refusal or junk command.
	let (server, sink) = server_living(Duration::from_secs(DEFAULT_MAX_SESSION_TIME_SECS));
	let mut client = Client::connect(&server);
	let started = Instant::now();
	client.send(OPEN).await;
	for _ in 0..7 {
		pass(Duration::from_secs(250)).await;
		client.send(b"RCPT TO:<bob@example.org>\r\n").await;
	}
	pass(Duration::from_secs(51)).await;
	let elapsed = started.elapsed();
	let output = client.finish().await;
	assert!(
		output.ends_with(TIME_UP),
		"the open transaction is cut with the exact 421 line"
	);
	assert_eq!(
		reply_codes(&output).len(),
		12,
		"greeting, EHLO, MAIL, 8 RCPT, 421"
	);
	assert!(
		started.elapsed() <= elapsed,
		"cut at 1800 s, not when the idle timeout ran out"
	);
	assert!(sink.messages().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_body_that_ends_past_the_limit_buys_no_second_message() {
	// The idle timeout granted after a long body is for a QUIT: a new
	// transaction pipelined after the dot is cut at its first command.
	let (server, sink) = server_living(Duration::from_secs(60));
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	client.send(b"DATA\r\n").await;
	client.wait_for("354 ").await;
	let second = body(FLOOR);
	for _ in 0..70 {
		client.send(&second).await;
		pass(Duration::from_secs(1)).await;
	}
	let mut next = b".\r\nMAIL FROM:<a@example.net>\r\nRCPT TO:<bob@example.org>\r\n".to_vec();
	next.extend_from_slice(b"DATA\r\nSubject: again\r\n\r\nhi\r\n.\r\nQUIT\r\n");
	client.send(&next).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "421"],
		"the first message is accepted, the next MAIL is cut"
	);
	assert!(output.ends_with(TIME_UP));
	assert_eq!(sink.messages().len(), 1, "no second message gets in");
}
