//! One sender cannot starve the others: a flood of messages to destinations
//! that never answer takes at most its share of the conversation slots,
//! and another sender's mail queued behind it goes out at once.

use std::time::Duration;

use super::*;
use crate::queue::tests::test_remote::{FakeRemote, Hang, Script};
use crate::smtp::session::AcceptedMessage;

const FLOOD: usize = 40;

fn store(spool: &FsSpool, sender: &str, recipient: &str, account: Option<&str>) {
	spool
		.store(
			&AcceptedMessage {
				reverse_path: sender.into(),
				recipients: vec![recipient.to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
				sender_verified: false,
			},
			account,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
}

#[tokio::test(start_paused = true)]
async fn a_flood_to_silent_destinations_leaves_room_for_another_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let remote = FakeRemote::default();
	// The flood is older, so a queue that works in spool order reaches all
	// of it first.
	for n in 0..FLOOD {
		let domain = format!("silent{n}.example");
		remote.script(&domain, Script::hang(Hang::Greeting));
		store(
			&spool,
			"flood@one.example",
			&format!("x@{domain}"),
			Some("flood"),
		);
	}
	store(&spool, "bob@two.example", "carol@ok.example", Some("bob"));
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	let started = tokio::time::Instant::now();

	// Only the first instant: every silent destination is still waited on.
	let _ = tokio::time::timeout(Duration::from_secs(1), worker.pass()).await;

	assert_eq!(
		remote.delivered_at("carol@ok.example"),
		Some(started),
		"the other sender's message went out at once"
	);
	let flooding: usize = (0..FLOOD)
		.map(|n| remote.connections(&format!("mx.silent{n}.example")))
		.sum();
	assert_eq!(flooding, 6, "the flood holds three quarters of the slots");
}

/// An exchanger that takes `secs` to answer each message.
fn slow(secs: u64) -> Script {
	Script {
		delay: Some(Duration::from_secs(secs)),
		..Script::default()
	}
}

#[tokio::test(start_paused = true)]
async fn senders_take_turns_for_the_slots() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let remote = FakeRemote::default();
	for n in 0..5 {
		let domain = format!("d{n}.example");
		remote.script(&domain, slow(10));
		store(
			&spool,
			"flood@one.example",
			&format!("x@{domain}"),
			Some("flood"),
		);
	}
	remote.script("ok.example", slow(10));
	store(&spool, "bob@two.example", "carol@ok.example", Some("bob"));
	let worker =
		Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example").with_concurrency(1, 1);
	let started = tokio::time::Instant::now();

	worker.pass().await.expect("pass");

	assert_eq!(
		remote.delivered_at("carol@ok.example"),
		Some(started + Duration::from_secs(20)),
		"second in turn, not after the five messages queued before it"
	);
}

/// Fill the slots from `account` with 100 messages to silent
/// destinations, each from a MAIL FROM domain of its own, and queue one
/// message of another account behind them; returns how many conversations
/// the flood had open, and whether the other message went out at once.
async fn flood_with_many_reverse_paths(account: Option<&str>) -> (usize, bool) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let remote = FakeRemote::default();
	for n in 0..100 {
		let domain = format!("silent{n}.example");
		remote.script(&domain, Script::hang(Hang::Greeting));
		store(
			&spool,
			&format!("flood@sender{n}.example"),
			&format!("x@{domain}"),
			account,
		);
	}
	store(&spool, "bob@two.example", "carol@ok.example", Some("bob"));
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	let started = tokio::time::Instant::now();

	let _ = tokio::time::timeout(Duration::from_secs(1), worker.pass()).await;

	let flooding = (0..100)
		.map(|n| remote.connections(&format!("mx.silent{n}.example")))
		.sum();
	(
		flooding,
		remote.delivered_at("carol@ok.example") == Some(started),
	)
}

#[tokio::test(start_paused = true)]
async fn many_reverse_paths_from_one_account_are_still_one_share() {
	assert_eq!(
		flood_with_many_reverse_paths(Some("flood")).await,
		(6, true)
	);
}

#[tokio::test(start_paused = true)]
async fn mail_without_an_account_shares_one_bucket_whatever_its_reverse_path() {
	assert_eq!(flood_with_many_reverse_paths(None).await, (6, true));
}
