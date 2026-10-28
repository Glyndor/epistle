//! The configured retry schedule applies to each pending recipient, spread
//! by the injected jitter, and the delay warning follows its configured age.

use super::*;
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use std::collections::BTreeMap;

fn spool_to(dir: &std::path::Path, recipients: &[&str]) -> (FsSpool, uuid::Uuid, u64) {
	let spool = FsSpool::open(dir).expect("open spool");
	let id = spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: recipients.iter().map(|r| r.to_string()).collect(),
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let created = id.get_timestamp().expect("v7").to_unix().0;
	(spool, id, created)
}

const SCHEDULE: RetrySchedule = RetrySchedule {
	base: 300,
	cap: 1000,
	delay_warning: 600,
};

use crate::queue::RetrySchedule;

#[tokio::test]
async fn each_pending_recipient_follows_the_configured_schedule() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id, start) = spool_to(dir.path(), &["bob@a.example", "dan@b.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"a.example",
		Script::rcpt("bob@a.example", "451 4.3.0 later"),
	);
	remote.script(
		"b.example",
		Script::rcpt("dan@b.example", "451 4.3.0 later"),
	);
	let mut worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_retry_schedule(SCHEDULE);
	worker.set_jitter(|| 1.1);

	worker.set_now(start + 1);
	worker.pass().await.expect("pass");
	let envelope = worker.spool.load_envelope(id).expect("envelope");
	for recipient in ["bob@a.example", "dan@b.example"] {
		let state = envelope.recipient_state(recipient);
		assert_eq!(state.attempts, 1);
		assert_eq!(
			state.next_attempt,
			start + 1 + 330,
			"base 300 spread by 1.1"
		);
	}

	// a.example recovers; only dan@ is still pending and backs off further.
	remote.script("a.example", Script::default());
	worker.set_now(start + 331);
	worker.pass().await.expect("pass");
	let envelope = worker.spool.load_envelope(id).expect("envelope");
	assert_eq!(envelope.pending(), vec!["dan@b.example".to_string()]);
	let dan = envelope.recipient_state("dan@b.example");
	assert_eq!(dan.attempts, 2);
	assert_eq!(dan.next_attempt, start + 331 + 660);
	assert_eq!(envelope.next_attempt, dan.next_attempt);

	worker.set_now(start + 991);
	worker.pass().await.expect("pass");
	let dan = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state("dan@b.example");
	assert_eq!(
		dan.next_attempt,
		start + 991 + 1100,
		"capped at 1000, spread"
	);
}

#[tokio::test]
async fn the_delay_warning_follows_its_configured_age() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, _, start) = spool_to(dir.path(), &["dan@b.example"]);
	let bounces = Arc::new(MemorySink::new());
	let mut worker = Worker::new(
		spool,
		Arc::new(super::base::DownConnector),
		"mail.sender.example",
	)
	.with_retry_schedule(SCHEDULE)
	.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>);
	worker.set_jitter(|| 1.0);

	worker.set_now(start + 599);
	worker.pass().await.expect("pass");
	assert!(bounces.messages().is_empty(), "not yet");

	worker.set_now(start + 1000);
	worker.pass().await.expect("pass");
	assert_eq!(bounces.messages().len(), 1, "warned at the configured age");
}
