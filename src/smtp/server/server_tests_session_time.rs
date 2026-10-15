//! The lifetime of one session: once it is over the client is answered
//! `421 4.4.2` and closed at the next command boundary, whether it was
//! waiting for a command or had one buffered, but never while a message
//! body is being received. Every test runs on tokio's paused clock.

use std::time::Duration;

use tokio::time::Instant;

use super::tests_data_rate::{Client, FLOOR, OPEN, body, pass, reply_codes, test_directory};
use super::tests_session_limits::{listen, one_slot_server, the_address_delivers_again};
use super::*;
use crate::smtp::sink::MemorySink;

/// The line a session past its lifetime is closed with.
const TIME_UP: &str = "421 4.4.2 session time limit reached\r\n";

/// A listener with the given session lifetime and an in-memory sink.
fn server_living(lifetime: Duration) -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_max_session_time(lifetime);
	(Arc::new(server), sink)
}

/// `OPEN` without its EHLO: a new transaction on a greeted session.
fn transaction() -> &'static [u8] {
	&OPEN[b"EHLO client.example.org\r\n".len()..]
}

#[tokio::test(start_paused = true)]
async fn a_chatty_session_is_cut_when_its_time_runs_out() {
	// A NOOP every 200 s keeps the idle timeout and the junk limit away,
	// and the last command is dripped: the default 1800 s still ends it.
	let (server, _sink) = server_living(Duration::from_secs(DEFAULT_MAX_SESSION_TIME_SECS));
	let mut client = Client::connect(&server);
	let started = Instant::now();
	client.send(b"EHLO client.example.org\r\n").await;
	for _ in 0..8 {
		pass(Duration::from_secs(200)).await;
		client.send(b"NOOP\r\n").await;
	}
	pass(Duration::from_secs(100)).await;
	client.send(b"NO").await;
	pass(Duration::from_secs(101)).await;
	let elapsed = started.elapsed();
	let output = client.finish().await;
	assert!(
		output.ends_with(TIME_UP),
		"the exact 421 line, then the close"
	);
	assert_eq!(
		reply_codes(&output).len(),
		11,
		"greeting, EHLO, 8 NOOP, 421"
	);
	assert!(
		started.elapsed() <= elapsed,
		"the session was over by 1801 s, not when the idle timeout ran out"
	);
}

#[tokio::test(start_paused = true)]
async fn a_message_body_crossing_the_limit_is_received_and_the_next_command_is_cut() {
	// The body starts at 30 s and comes at the floor for 60 s, past the
	// 60 s lifetime: the message is delivered, and the NOOP already sent
	// after its dot is answered 421.
	let (server, sink) = server_living(Duration::from_secs(60));
	let mut client = Client::connect(&server);
	client.send(b"EHLO client.example.org\r\n").await;
	pass(Duration::from_secs(30)).await;
	client.send(transaction()).await;
	client.send(b"DATA\r\n").await;
	client.wait_for("354 ").await;
	let second = body(FLOOR);
	for _ in 0..60 {
		client.send(&second).await;
		pass(Duration::from_secs(1)).await;
	}
	client.send(b".\r\nNOOP\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "421"],
		"the message is accepted, the command after it is cut"
	);
	assert!(output.ends_with(TIME_UP));
	assert_eq!(sink.messages().len(), 1, "the message was delivered");
}

#[tokio::test(start_paused = true)]
async fn a_bdat_transaction_crossing_the_limit_may_finish() {
	// Between chunks the transaction is still open: a NOOP there is
	// answered, the LAST chunk is delivered, and only then is it cut.
	let (server, sink) = server_living(Duration::from_secs(60));
	let mut client = Client::connect(&server);
	client.send(b"EHLO client.example.org\r\n").await;
	pass(Duration::from_secs(50)).await;
	client.send(transaction()).await;
	client.send(b"BDAT 2048\r\n").await;
	client.send(&[b'x'; 2048]).await;
	pass(Duration::from_secs(20)).await;
	client.send(b"NOOP\r\n").await;
	client.send(b"BDAT 5 LAST\r\nhelloNOOP\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "250", "250", "421"],
		"the chunks and the NOOP between them are answered, the NOOP after is cut"
	);
	assert_eq!(sink.messages().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_lifetime_of_zero_never_cuts() {
	let (server, _sink) = server_living(Duration::ZERO);
	let mut client = Client::connect(&server);
	client.send(b"EHLO client.example.org\r\n").await;
	for _ in 0..12 {
		pass(Duration::from_secs(250)).await;
		client.send(b"NOOP\r\n").await;
	}
	client.send(b"QUIT\r\n").await;
	let output = client.finish().await;
	let codes = reply_codes(&output);
	assert_eq!(codes.len(), 15, "greeting, EHLO, 12 NOOP and the QUIT");
	assert!(output.ends_with("221 2.0.0 closing connection\r\n"));
}

#[tokio::test(start_paused = true)]
async fn a_cut_for_the_lifetime_gives_the_slot_back() {
	let budget = Arc::new(MemoryBudget::with_cap(4096));
	let (server, sink) = one_slot_server(&budget, |server| {
		server.with_max_session_time(Duration::from_secs(60))
	});
	let (arrive, serving) = listen(&server);
	let (old, stream) = tokio::io::duplex(64 * 1024);
	arrive.send(stream).expect("first connection");
	let mut old = Client::over(old);
	old.send(OPEN).await;
	pass(Duration::from_secs(30)).await;
	old.send(b"NOOP\r\n").await;
	pass(Duration::from_secs(31)).await;
	let output = old.finish().await;
	assert!(output.ends_with(TIME_UP), "the old session is cut");
	assert_eq!(budget.used(), 0);
	the_address_delivers_again(&arrive, &sink).await;
	serving.abort();
}

#[tokio::test(start_paused = true)]
async fn an_auth_exchange_answered_slowly_is_cut_when_the_time_runs_out() {
	// AUTH LOGIN waits for one continuation line at a time: a client that
	// answers each one just inside the idle timeout is still cut on time.
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_directory(super::tests_auth::directory_with_password())
		.with_max_session_time(Duration::from_secs(60))
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Implicit,
		);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = super::tests_auth::connector(cert)
		.connect(name, client)
		.await
		.expect("handshake");
	let started = Instant::now();
	let mut seen = String::new();
	for (line, wanted) in [
		(&b"EHLO c.example.org\r\n"[..], "250 "),
		(b"AUTH LOGIN\r\n", "334 "),
	] {
		tls.write_all(line).await.expect("write");
		while !seen.contains(wanted) || !seen.ends_with("\r\n") {
			seen.push_str(&super::tests_auth::reply(&mut tls).await);
		}
	}
	pass(Duration::from_secs(30)).await;
	tls.write_all(b"YWxpY2U=\r\n").await.expect("username");
	pass(Duration::from_secs(31)).await;
	let mut rest = Vec::new();
	let _ = tls.read_to_end(&mut rest).await;
	let rest = String::from_utf8_lossy(&rest);
	assert!(
		rest.ends_with(TIME_UP),
		"the exchange is cut with the exact 421 line: {rest:?}"
	);
	assert!(
		started.elapsed() <= Duration::from_secs(61),
		"cut when the lifetime ran out, not when the idle timeout did"
	);
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_quit_sent_with_the_last_body_line_is_still_answered() {
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
	client.send(b".\r\nQUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"],
		"a client leaving after its message is not answered 421"
	);
	assert_eq!(sink.messages().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn after_a_long_message_the_next_command_gets_one_idle_timeout() {
	// The body ends past the lifetime: the client is not closed under its
	// feet, the command it sends next is answered 421, and a client that
	// sends none is closed once the idle timeout is over.
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
	client.send(b".\r\n").await;
	client.wait_for("250 ").await;
	pass(Duration::from_secs(200)).await;
	client.send(b"NOOP\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "421"]
	);
	assert!(output.ends_with(TIME_UP));
	assert_eq!(sink.messages().len(), 1);
}
