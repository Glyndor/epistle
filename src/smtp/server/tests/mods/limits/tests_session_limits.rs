//! Limits on how long a connection may be held without bringing a message
//! closer to delivery: the number of commands without progress and the
//! age of the session. Each cut gives the memory budget and the per-IP
//! slot back. Every test runs on tokio's paused clock.

use tokio::sync::mpsc;

use super::super::rate::tests_data_rate::{Arrivals, Client, OPEN, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

/// The line a session past its junk-command limit is closed with.
const TOO_MANY: &str = "421 4.7.0 too many commands without progress, closing connection\r\n";

/// A listener for one address that admits one connection from it at a time,
/// with a budget for one small message.
pub(in crate::smtp::server::tests::mods) fn one_slot_server(
	budget: &Arc<MemoryBudget>,
	configure: impl FnOnce(Server) -> Server,
) -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_max_message_size(4096)
		.with_memory_budget(Arc::clone(budget))
		.with_max_connections_per_ip(1);
	(Arc::new(configure(server)), sink)
}

/// Start `server` on a listener whose connections the test hands over.
pub(in crate::smtp::server::tests::mods) fn listen(
	server: &Arc<Server>,
) -> (
	mpsc::UnboundedSender<tokio::io::DuplexStream>,
	tokio::task::JoinHandle<std::io::Result<()>>,
) {
	let (arrive, next) = mpsc::unbounded_channel();
	let listener = Arrivals {
		next: tokio::sync::Mutex::new(next),
		peer: "203.0.113.7:4000".parse().expect("peer"),
	};
	(arrive, tokio::spawn(Arc::clone(server).serve_on(listener)))
}

/// Connect again from the same address and deliver one message: possible
/// only once the earlier connection gave its slot and its octets back.
pub(in crate::smtp::server::tests::mods) async fn the_address_delivers_again(
	arrive: &mpsc::UnboundedSender<tokio::io::DuplexStream>,
	sink: &MemorySink,
) {
	let (client, stream) = tokio::io::duplex(64 * 1024);
	arrive.send(stream).expect("next connection");
	let mut client = Client::over(client);
	let mut message = OPEN.to_vec();
	message.extend_from_slice(b"DATA\r\nSubject: hi\r\n\r\n");
	for _ in 0..30 {
		message.extend_from_slice(&[&[b'y'; 98][..], b"\r\n"].concat());
	}
	message.extend_from_slice(b".\r\nQUIT\r\n");
	client.send(&message).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"],
		"the same address connects again and its message fits the budget"
	);
	assert_eq!(sink.messages().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_101st_noop_on_the_wire_is_answered_421_and_closed() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
	);
	let mut client = Client::connect(&server);
	client.send(b"EHLO client.example.org\r\n").await;
	client.send(&b"NOOP\r\n".repeat(101)).await;
	let output = client.finish().await;
	let codes = reply_codes(&output);
	assert_eq!(codes.len(), 103, "greeting, EHLO, 100 NOOP and the cut");
	assert!(codes[..102].iter().all(|code| *code != "421"));
	assert!(
		output.ends_with(TOO_MANY),
		"the exact 421 line, then the close"
	);
}

#[tokio::test(start_paused = true)]
async fn a_junk_cut_gives_the_budget_and_the_slot_back() {
	// A BDAT chunk is held on the budget while the client sends NOOPs.
	let budget = Arc::new(MemoryBudget::with_cap(4096));
	let (server, sink) = one_slot_server(&budget, |server| server);
	let (arrive, serving) = listen(&server);
	let (junk, stream) = tokio::io::duplex(64 * 1024);
	arrive.send(stream).expect("first connection");
	let mut junk = Client::over(junk);
	junk.send(OPEN).await;
	junk.send(b"BDAT 100\r\n").await;
	junk.send(&[b'x'; 100]).await;
	junk.wait_for("chunk received").await;
	assert_eq!(budget.used(), 100, "the chunk is held");
	junk.send(&b"NOOP\r\n".repeat(101)).await;
	let output = junk.finish().await;
	assert!(output.ends_with(TOO_MANY), "the junk client is cut");
	assert_eq!(budget.used(), 0, "the chunk went back with the session");
	the_address_delivers_again(&arrive, &sink).await;
	serving.abort();
}

#[tokio::test(start_paused = true)]
async fn a_listener_with_no_junk_limit_keeps_answering() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_junk_command_limit(0),
	);
	let mut client = Client::connect(&server);
	client.send(b"EHLO client.example.org\r\n").await;
	client.send(&b"NOOP\r\n".repeat(150)).await;
	client.send(b"QUIT\r\n").await;
	let output = client.finish().await;
	let codes = reply_codes(&output);
	assert_eq!(codes.len(), 153, "greeting, EHLO, 150 NOOP and the QUIT");
	assert!(
		codes[1..152].iter().all(|code| *code == "250"),
		"no limit, no cut"
	);
	assert!(output.ends_with("221 2.0.0 closing connection\r\n"));
}

#[tokio::test(start_paused = true)]
async fn a_relay_delivering_a_list_with_many_unknown_recipients_is_not_cut() {
	// Three messages of a list, each to 38 addresses that no longer exist
	// and two that do, in runs shorter than the consecutive-error guard:
	// 114 refusals in one session, and every message is delivered.
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
	);
	let mut client = Client::connect(&server);
	let mut session = b"EHLO lists.example.net\r\n".to_vec();
	for message in 0..3 {
		session.extend_from_slice(b"MAIL FROM:<list@lists.example.net>\r\n");
		for run in 0..2 {
			for unknown in 0..19 {
				let line = format!("RCPT TO:<gone{message}x{run}x{unknown}@example.org>\r\n");
				session.extend_from_slice(line.as_bytes());
			}
			session.extend_from_slice(b"RCPT TO:<bob@example.org>\r\n");
		}
		session.extend_from_slice(b"DATA\r\nSubject: list\r\n\r\nhello\r\n.\r\n");
	}
	session.extend_from_slice(b"QUIT\r\n");
	client.send(&session).await;
	let output = client.finish().await;
	assert!(
		!output.contains("421"),
		"no refusal count closes a relay whose messages are accepted"
	);
	let codes = reply_codes(&output);
	assert_eq!(codes.iter().filter(|code| **code == "550").count(), 114);
	assert_eq!(
		sink.messages().len(),
		3,
		"every message of the list arrives"
	);
	assert!(output.ends_with("221 2.0.0 closing connection\r\n"));
}

#[tokio::test(start_paused = true)]
async fn a_message_the_server_refuses_does_not_forgive_earlier_refusals() {
	// The same list traffic as above, but every message is refused once
	// its body is in (here as a mail loop): no message is accepted, so the
	// 101st refused recipient closes the session.
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
	);
	let mut client = Client::connect(&server);
	let looping = "Received: from relay.example.net\r\n".repeat(100);
	let mut session = b"EHLO lists.example.net\r\n".to_vec();
	for message in 0..3 {
		session.extend_from_slice(b"MAIL FROM:<list@lists.example.net>\r\n");
		for run in 0..2 {
			for unknown in 0..19 {
				let line = format!("RCPT TO:<gone{message}x{run}x{unknown}@example.org>\r\n");
				session.extend_from_slice(line.as_bytes());
			}
			session.extend_from_slice(b"RCPT TO:<bob@example.org>\r\n");
		}
		session.extend_from_slice(b"DATA\r\n");
		session.extend_from_slice(looping.as_bytes());
		session.extend_from_slice(b"Subject: list\r\n\r\nhello\r\n.\r\n");
	}
	session.extend_from_slice(b"QUIT\r\n");
	client.send(&session).await;
	let output = client.finish().await;
	let codes = reply_codes(&output);
	assert_eq!(
		codes.iter().filter(|code| **code == "554").count(),
		2,
		"the first two messages are refused as loops"
	);
	assert_eq!(
		codes.iter().filter(|code| **code == "550").count(),
		100,
		"100 refused recipients are answered"
	);
	assert!(
		output.ends_with(TOO_MANY),
		"the 101st refused recipient closes the session: nothing was accepted"
	);
	assert!(sink.messages().is_empty());
}

#[tokio::test(start_paused = true)]
async fn command_lines_that_are_not_utf8_count_as_refusals() {
	// Each line that is not UTF-8 is answered 500 like any syntax error, and
	// counts like one: a recipient accepted between them keeps the
	// consecutive-error guard away, but the 101st still closes the session.
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
	);
	let mut client = Client::connect(&server);
	let mut session = b"EHLO client.example.org\r\n".to_vec();
	for pairs in [60, 41] {
		session.extend_from_slice(
			b"RSET\r\nMAIL FROM:<a@example.net>\r\nRCPT TO:<bob@example.org>\r\n",
		);
		for _ in 0..pairs {
			session.extend_from_slice(b"\xff\xfe\r\nRCPT TO:<bob@example.org>\r\n");
		}
	}
	session.extend_from_slice(b"QUIT\r\n");
	client.send(&session).await;
	let output = client.finish().await;
	let codes = reply_codes(&output);
	assert_eq!(
		codes.iter().filter(|code| **code == "500").count(),
		100,
		"100 lines that are not UTF-8 are answered"
	);
	assert!(
		output.ends_with(TOO_MANY),
		"the 101st line that is not UTF-8 closes the session"
	);
}

#[tokio::test(start_paused = true)]
async fn twenty_lines_in_a_row_that_are_not_utf8_hit_the_error_guard() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
	);
	let mut client = Client::connect(&server);
	let mut session = b"EHLO client.example.org\r\n".to_vec();
	session.extend_from_slice(&b"\xff\xfe\r\n".repeat(25));
	client.send(&session).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output).len(),
		22,
		"greeting, EHLO, 19 x 500, 421"
	);
	assert!(
		output.ends_with("421 4.7.0 too many errors, closing connection\r\n"),
		"the consecutive-error guard sees them too"
	);
}
