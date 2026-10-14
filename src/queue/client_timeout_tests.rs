//! Every step of an outbound conversation is bounded: a server that accepts
//! the connection and then stops answering fails the conversation
//! transiently after the RFC 5321 section 4.5.3.2 wait for that step, never
//! sooner and never later. The clock is tokio's paused clock, so each test
//! takes no real time.

use std::time::Duration;

use super::*;
use crate::queue::resolver::Connector;
use crate::queue::test_remote::{FakeRemote, Hang, Script};
use crate::queue::timeouts;

const DOMAIN: &str = "slow.example";
const RECIPIENT: &str = "bob@slow.example";

/// One conversation with an exchanger that stops at `hang`: what it gave
/// back, and how long it took on the tokio clock.
async fn converse_with(
	hang: Hang,
	data: &[u8],
) -> (Result<Vec<RecipientResult>, DeliveryError>, Duration) {
	let remote = FakeRemote::default();
	remote.script(DOMAIN, Script::hang(hang));
	let connection = remote.connect(DOMAIN, None).await.expect("connect");
	let started = tokio::time::Instant::now();
	let result = deliver_each(
		connection.stream,
		&connection.host,
		"mail.sender.example",
		"alice@sender.example",
		&[RECIPIENT.to_string()],
		data,
		false,
		None,
		&TlsaRrset::Absent,
		OutboundTls::Opportunistic,
		&mut None,
	)
	.await;
	(result, started.elapsed())
}

fn assert_took(elapsed: Duration, limit: Duration) {
	assert!(
		elapsed >= limit && elapsed < limit + Duration::from_secs(1),
		"expected to give up after {limit:?}, gave up after {elapsed:?}"
	);
}

fn timed_out(limit: Duration, what: &str) -> DeliveryError {
	DeliveryError::Transient(format!(
		"timed out after {}s waiting for {what}",
		limit.as_secs()
	))
}

/// A step before any recipient is answered fails the whole conversation.
async fn session_step(hang: Hang, limit: Duration, what: &str) {
	let (result, elapsed) = converse_with(hang, b"Subject: hi\r\n\r\nbody\r\n").await;
	assert_eq!(result, Err(timed_out(limit, what)), "{hang:?}");
	assert_took(elapsed, limit);
}

/// A step after the recipient was accepted fails that recipient.
async fn message_step(hang: Hang, data: &[u8], limit: Duration, what: &str) {
	let (result, elapsed) = converse_with(hang, data).await;
	assert_eq!(
		result,
		Ok(vec![(RECIPIENT.to_string(), Err(timed_out(limit, what)))]),
		"{hang:?}"
	);
	assert_took(elapsed, limit);
}

#[tokio::test(start_paused = true)]
async fn a_missing_greeting_gives_up_after_five_minutes() {
	session_step(Hang::Greeting, timeouts::GREETING, "the greeting").await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_ehlo_gives_up_after_five_minutes() {
	session_step(Hang::Ehlo, timeouts::COMMAND, "a command reply").await;
}

#[tokio::test(start_paused = true)]
async fn a_stalled_tls_handshake_gives_up_after_a_minute() {
	session_step(
		Hang::TlsHandshake,
		timeouts::TLS_HANDSHAKE,
		"the TLS handshake",
	)
	.await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_mail_gives_up_after_five_minutes() {
	session_step(Hang::Mail, timeouts::COMMAND, "a command reply").await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_rcpt_gives_up_after_five_minutes() {
	session_step(Hang::Rcpt, timeouts::RCPT, "the RCPT reply").await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_data_gives_up_after_two_minutes() {
	message_step(
		Hang::DataInit,
		b"Subject: hi\r\n\r\nbody\r\n",
		timeouts::DATA_INIT,
		"the DATA reply",
	)
	.await;
}

#[tokio::test(start_paused = true)]
async fn a_server_that_stops_reading_the_message_gives_up_after_three_minutes() {
	// Larger than the pipe, so the client blocks writing once the remote
	// stops reading.
	let mut data = b"Subject: big\r\n\r\n".to_vec();
	data.extend(
		std::iter::repeat_n(b"0123456789abcdef0123456789abcdef\r\n".as_slice(), 10_000).flatten(),
	);
	message_step(
		Hang::DataBody,
		&data,
		timeouts::DATA_BLOCK,
		"the message data to be read",
	)
	.await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_final_dot_gives_up_after_ten_minutes() {
	message_step(
		Hang::DataEnd,
		b"Subject: hi\r\n\r\nbody\r\n",
		timeouts::DATA_END,
		"the reply to the message",
	)
	.await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_quit_keeps_the_delivery_and_waits_briefly() {
	let (result, elapsed) = converse_with(Hang::Quit, b"Subject: hi\r\n\r\nbody\r\n").await;
	assert_eq!(result, Ok(vec![(RECIPIENT.to_string(), Ok(()))]));
	assert_took(elapsed, timeouts::QUIT);
}
