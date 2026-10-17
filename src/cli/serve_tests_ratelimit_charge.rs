//! When a submission is charged: once, per recipient, when the message is
//! accepted. A transaction that ends in `RSET`, a message over the limit and
//! a message the server refuses after DATA all cost nothing, over a real
//! SMTP listener built like `serve` builds one.

use tokio::io::AsyncWriteExt;
use tokio_rustls::client::TlsStream;

use super::tests_ratelimit::{
	auth_plain, build_smtp_server, expect_reply, expect_reply_first_digit, ratelimit_config,
	spawn_smtp_listener, tls_connector, tls_session,
};
use crate::tls::test_support::acceptor_and_cert;

type Tls = TlsStream<tokio::net::TcpStream>;

const OVER_LIMIT: &str = "450 4.7.1 sending rate limit exceeded; retry later";

/// A listener whose per-account limit is `per_min`, and a signed-in
/// session as alice.
async fn signed_in(dir: &std::path::Path, per_min: u32) -> (Tls, tokio::task::JoinHandle<()>) {
	let config = ratelimit_config(dir, per_min);
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(&config, crate::tls::ReloadableAcceptor::new(acceptor), None);
	let (addr, task) = spawn_smtp_listener(server).await;
	let mut tls = tls_session(addr, tls_connector(cert)).await;
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = expect_reply(&mut tls, "250").await;
	let plain = auth_plain("alice", crate::smtp::auth::tests::fixture_password());
	tls.write_all(format!("AUTH PLAIN {plain}\r\n").as_bytes())
		.await
		.expect("auth");
	let _ = expect_reply(&mut tls, "235").await;
	(tls, task)
}

/// Send one command line and return its (single-line) reply.
async fn command(tls: &mut Tls, line: &str) -> String {
	tls.write_all(format!("{line}\r\n").as_bytes())
		.await
		.expect("write");
	expect_reply_first_digit(tls).await
}

/// One transaction from alice to `to` with `headers` before the body.
/// The reply that ended it: `MAIL FROM`'s when that refuses, else the
/// reply to the end of the data.
async fn message(tls: &mut Tls, to: &[&str], headers: &str) -> String {
	let mail = command(tls, "MAIL FROM:<alice@example.org>").await;
	if !mail.starts_with("250 ") {
		return mail;
	}
	for recipient in to {
		let _ = command(tls, &format!("RCPT TO:<{recipient}>")).await;
	}
	let data = command(tls, "DATA").await;
	assert!(data.starts_with("354 "), "{data}");
	command(
		tls,
		&format!("{headers}From: alice@example.org\r\n\r\nhello\r\n."),
	)
	.await
}

#[tokio::test]
async fn a_transaction_ended_by_rset_costs_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut tls, task) = signed_in(dir.path(), 1).await;
	for _ in 0..3 {
		assert!(
			command(&mut tls, "MAIL FROM:<alice@example.org>")
				.await
				.starts_with("250 ")
		);
		assert!(
			command(&mut tls, "MAIL FROM:<alice@example.org>")
				.await
				.starts_with("503 "),
			"a second MAIL FROM in one transaction is out of sequence"
		);
		assert!(command(&mut tls, "RSET").await.starts_with("250 "));
	}
	let accepted = message(&mut tls, &["bob@example.org"], "").await;
	assert!(accepted.starts_with("250 "), "{accepted}");
	assert_eq!(
		message(&mut tls, &["bob@example.org"], "").await,
		OVER_LIMIT
	);
	task.abort();
}

#[tokio::test]
async fn a_message_over_the_limit_costs_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut tls, task) = signed_in(dir.path(), 3).await;
	let two = ["bob@example.org", "carol@example.org"];
	assert!(message(&mut tls, &two, "").await.starts_with("250 "));
	assert_eq!(
		message(&mut tls, &two, "").await,
		OVER_LIMIT,
		"two more recipients would make four"
	);
	assert!(
		message(&mut tls, &["bob@example.org"], "")
			.await
			.starts_with("250 "),
		"the refused message took nothing, so the third recipient fits"
	);
	assert_eq!(
		message(&mut tls, &["bob@example.org"], "").await,
		OVER_LIMIT
	);
	task.abort();
}

#[tokio::test]
async fn pipelined_recipients_are_each_charged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut tls, task) = signed_in(dir.path(), 1).await;
	tls.write_all(
		b"MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@example.org>\r\n\
		  RCPT TO:<carol@example.org>\r\nDATA\r\n",
	)
	.await
	.expect("pipelined");
	// The replies to a pipelined group may come back in one write.
	let mut replies = String::new();
	while replies.lines().count() < 4 {
		let mut chunk = [0u8; 512];
		let read = tokio::time::timeout(
			std::time::Duration::from_secs(10),
			tokio::io::AsyncReadExt::read(&mut tls, &mut chunk),
		)
		.await
		.expect("pipelined replies in time")
		.expect("read");
		assert!(read > 0, "closed after {replies:?}");
		replies.push_str(&String::from_utf8_lossy(&chunk[..read]));
	}
	let codes: Vec<&str> = replies.lines().map(|line| &line[..4]).collect();
	assert_eq!(codes, ["250 ", "250 ", "250 ", "354 "], "{replies}");
	let end = command(&mut tls, "From: alice@example.org\r\n\r\nhi\r\n.").await;
	assert_eq!(end, OVER_LIMIT, "two recipients do not fit a limit of one");
	assert!(
		message(&mut tls, &["bob@example.org"], "")
			.await
			.starts_with("250 ")
	);
	task.abort();
}

#[tokio::test]
async fn only_the_recipients_accepted_at_rcpt_are_charged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut tls, task) = signed_in(dir.path(), 2).await;
	let mixed = ["bob@example.org", "nobody@example.org"];
	assert!(message(&mut tls, &mixed, "").await.starts_with("250 "));
	assert!(
		message(&mut tls, &["carol@example.org"], "")
			.await
			.starts_with("250 ")
	);
	assert_eq!(
		message(&mut tls, &["bob@example.org"], "").await,
		OVER_LIMIT
	);
	task.abort();
}

#[tokio::test]
async fn a_message_refused_after_data_gets_its_units_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut tls, task) = signed_in(dir.path(), 1).await;
	// The listener refuses a looping message after the session accepted
	// it (`554 5.4.6`); its charge must come back.
	let looping = "Received: from a by b; Thu, 1 Jan 2026 00:00:00 +0000\r\n"
		.repeat(crate::smtp::trace::RECEIVED_HOP_LIMIT);
	let refused = message(&mut tls, &["bob@example.org"], &looping).await;
	assert!(refused.starts_with("554 5.4.6"), "{refused}");
	let accepted = message(&mut tls, &["bob@example.org"], "").await;
	assert!(
		accepted.starts_with("250 "),
		"the refused message took nothing: {accepted}"
	);
	assert_eq!(
		message(&mut tls, &["bob@example.org"], "").await,
		OVER_LIMIT
	);
	task.abort();
}

#[tokio::test]
async fn bdat_is_charged_per_recipient_like_data() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut tls, task) = signed_in(dir.path(), 2).await;
	assert!(
		command(&mut tls, "MAIL FROM:<alice@example.org>")
			.await
			.starts_with("250 ")
	);
	for recipient in ["bob@example.org", "carol@example.org"] {
		let _ = command(&mut tls, &format!("RCPT TO:<{recipient}>")).await;
	}
	let body = "From: alice@example.org\r\n\r\nhi\r\n";
	tls.write_all(format!("BDAT {} LAST\r\n{body}", body.len()).as_bytes())
		.await
		.expect("bdat");
	let end = expect_reply_first_digit(&mut tls).await;
	assert!(end.starts_with("250 "), "{end}");
	assert_eq!(
		command(&mut tls, "MAIL FROM:<alice@example.org>").await,
		OVER_LIMIT
	);
	task.abort();
}
