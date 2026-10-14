//! Several conversations run at once: a slow destination does not hold up
//! the others, no destination gets more than its share, and a recipient is
//! never in two conversations, even when two passes overlap or one is cut
//! short. The clock is tokio's paused clock.

use std::time::Duration;

use super::*;
use crate::queue::test_remote::{FakeRemote, Hang, Script};
use crate::smtp::session::AcceptedMessage;
use crate::storage::RecipientStatus;

const SENDER: &str = "alice@sender.example";

/// Spool one message per recipient, oldest first.
fn spool_each(dir: &std::path::Path, recipients: &[&str]) -> FsSpool {
	let spool = FsSpool::open(dir).expect("open spool");
	for recipient in recipients {
		spool
			.store(
				&AcceptedMessage {
					reverse_path: SENDER.into(),
					recipients: vec![recipient.to_string()],
					data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					no_dsn: Vec::new(),
				},
				None,
				&std::collections::BTreeMap::new(),
			)
			.expect("store");
	}
	spool
}

/// An exchanger that takes `secs` to answer each message.
fn slow(secs: u64) -> Script {
	Script {
		delay: Some(Duration::from_secs(secs)),
		..Script::default()
	}
}

#[tokio::test(start_paused = true)]
async fn a_hung_destination_does_not_hold_up_a_healthy_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The hung destination's message is the older one, so a queue that
	// works one conversation at a time reaches it first.
	let spool = spool_each(dir.path(), &["bob@hung.example", "carol@ok.example"]);
	let remote = FakeRemote::default();
	remote.script("hung.example", Script::hang(Hang::Greeting));
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	let started = tokio::time::Instant::now();

	let delivered = worker.pass().await.expect("pass");

	let healthy = remote
		.delivered_at("carol@ok.example")
		.expect("the healthy destination got its message");
	assert!(
		healthy - started < Duration::from_secs(1),
		"the healthy destination waited {:?} behind the hung one",
		healthy - started
	);
	assert_eq!(delivered, 1);
	assert_eq!(remote.copies("bob@hung.example"), 0);
	let left = worker.spool.list().expect("list");
	assert_eq!(left.len(), 1, "only the hung destination's message is left");
	let envelope = worker.spool.load_envelope(left[0]).expect("envelope");
	let state = envelope.recipient_state("bob@hung.example");
	assert_eq!(state.status, RecipientStatus::Pending);
	assert_eq!(state.attempts, 1);
	assert_eq!(
		state.last_error.as_deref(),
		Some("timed out after 300s waiting for the greeting")
	);
}

#[tokio::test(start_paused = true)]
async fn one_destination_gets_two_conversations_at_a_time_by_default() {
	let dir = tempfile::tempdir().expect("tempdir");
	let recipients = [
		"a@busy.example",
		"b@busy.example",
		"c@busy.example",
		"d@busy.example",
		"e@busy.example",
	];
	let spool = spool_each(dir.path(), &recipients);
	let remote = FakeRemote::default();
	remote.script("busy.example", slow(10));
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");

	assert_eq!(worker.pass().await.expect("pass"), 5);

	assert_eq!(remote.most_at_once("busy.example"), 2);
	for recipient in recipients {
		assert_eq!(remote.copies(recipient), 1, "{recipient}");
	}
	assert!(worker.spool.list().expect("list").is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_per_destination_and_total_caps_are_configurable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let recipients = [
		"a@one.example",
		"b@one.example",
		"c@one.example",
		"d@one.example",
		"e@two.example",
		"f@three.example",
		"g@four.example",
		"h@five.example",
	];
	let spool = spool_each(dir.path(), &recipients);
	let remote = FakeRemote::default();
	for domain in [
		"one.example",
		"two.example",
		"three.example",
		"four.example",
		"five.example",
	] {
		remote.script(domain, slow(10));
	}
	let worker =
		Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example").with_concurrency(4, 3);

	assert_eq!(worker.pass().await.expect("pass"), 8);

	assert_eq!(remote.most_at_once("one.example"), 3);
	assert_eq!(remote.most_at_once_total(), 4);
	for recipient in recipients {
		assert_eq!(remote.copies(recipient), 1, "{recipient}");
	}
}

#[tokio::test(start_paused = true)]
async fn two_overlapping_passes_never_carry_the_same_recipient() {
	let dir = tempfile::tempdir().expect("tempdir");
	let recipients = ["a@x.example", "b@x.example", "c@y.example"];
	let spool = spool_each(dir.path(), &recipients);
	let remote = FakeRemote::default();
	remote.script("x.example", slow(30));
	remote.script("y.example", slow(30));
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");

	let (first, second) = tokio::join!(worker.pass(), worker.pass());

	assert_eq!(first.expect("first pass") + second.expect("second pass"), 3);
	for recipient in recipients {
		assert_eq!(remote.copies(recipient), 1, "{recipient}");
	}
	assert!(worker.spool.list().expect("list").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_conversation_cut_short_leaves_its_recipient_pending_and_free() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_each(dir.path(), &["bob@remote.example"]);
	let remote = FakeRemote::default();
	// The whole message goes out, then the remote says nothing: the pass is
	// cut short there, as a crash or a shutdown would.
	remote.script("remote.example", Script::hang(Hang::DataEnd));
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");

	let cut = tokio::time::timeout(Duration::from_secs(60), worker.pass()).await;
	assert!(cut.is_err(), "the pass was still waiting for the remote");

	let id = worker.spool.list().expect("list")[0];
	let state = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state("bob@remote.example");
	assert_eq!(
		state.status,
		RecipientStatus::Pending,
		"never delivered without a 250"
	);
	assert_eq!(
		state.attempts, 0,
		"the attempt that was cut short has no outcome"
	);

	// The next pass, in this process or after a restart, takes it again.
	remote.script("remote.example", Script::default());
	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert_eq!(remote.copies("bob@remote.example"), 1);
	assert!(worker.spool.list().expect("list").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_restarted_worker_retries_what_a_cut_short_one_left() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_each(dir.path(), &["bob@remote.example"]);
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::hang(Hang::DataEnd));
	let first = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	let cut = tokio::time::timeout(Duration::from_secs(60), first.pass()).await;
	assert!(cut.is_err());
	drop(first);

	remote.script("remote.example", Script::default());
	let spool = FsSpool::open(dir.path()).expect("reopen spool");
	let second = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	assert_eq!(second.pass().await.expect("pass"), 1);
	assert_eq!(remote.copies("bob@remote.example"), 1);
}

#[tokio::test(start_paused = true)]
async fn the_running_worker_keeps_scanning_while_a_destination_hangs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_each(dir.path(), &["bob@hung.example"]);
	let remote = FakeRemote::default();
	remote.script("hung.example", Script::hang(Hang::DataEnd));
	let worker = Arc::new(Worker::new(
		spool,
		Arc::new(remote.clone()),
		"mail.sender.example",
	));
	let running = tokio::spawn(worker.run(Duration::from_secs(30)));
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert_eq!(remote.connections("mx.hung.example"), 1);

	// A message submitted while the hung conversation waits its ten minutes
	// goes out on the next scan, not after it.
	let started = tokio::time::Instant::now();
	spool_each(dir.path(), &["carol@ok.example"]);
	tokio::time::sleep(Duration::from_secs(31)).await;

	let delivered = remote.delivered_at("carol@ok.example");
	running.abort();
	let delivered = delivered.expect("the new message was delivered");
	assert!(delivered - started <= Duration::from_secs(30));
	assert_eq!(
		remote.connections("mx.hung.example"),
		1,
		"never retried meanwhile"
	);
}
