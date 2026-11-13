//! Delivery log tests for deduplicated deferrals.

use super::*;

/// A worker with the delivery log on, its clock at `start`, sending one
/// message to `bob@remote.example`.
fn retrying_worker(dir: &std::path::Path, remote: &FakeRemote, start: u64) -> Worker {
	let spool = spool_with(
		dir,
		&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["bob@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
			sender_verified: false,
		},
	);
	let mut worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_delivery_log(DeliveryLog::open(dir, 30));
	worker.set_jitter(|| 1.0);
	worker.set_now(start);
	worker
}

/// Run a pass a day after `day - 1`, well past any retry wait.
async fn pass_on_day(worker: &Worker, start: u64, day: u64) {
	worker.set_now(start + day * 86_400 / 8);
	worker.pass().await.expect("pass");
}

fn outcomes(dir: &std::path::Path) -> Vec<(crate::storage::DeliveryOutcome, Option<String>, u32)> {
	let mut records = load_records(dir);
	records.sort_by_key(|record| (record.time, record.attempt));
	records
		.into_iter()
		.map(|record| (record.outcome, record.reply, record.attempt))
		.collect()
}

#[tokio::test]
async fn a_recipient_deferred_again_for_the_same_reason_is_logged_once() {
	use crate::storage::DeliveryOutcome::{Deferred, Delivered};
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let busy = "450 4.2.1 mailbox busy, try later";
	remote.script("remote.example", Script::rcpt("bob@remote.example", busy));
	let start = 1_700_000_000;
	let worker = retrying_worker(dir.path(), &remote, start);

	for day in 0..3 {
		pass_on_day(&worker, start, day).await;
	}
	assert_eq!(
		outcomes(dir.path()),
		vec![(Deferred, Some(busy.to_string()), 1)],
		"three attempts deferred for one reason make one record"
	);
	let id = worker.spool.list().expect("list")[0];
	let state = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state("bob@remote.example");
	assert_eq!(state.attempts, 3, "every attempt still counts");

	let full = "452 4.2.2 mailbox full";
	remote.script("remote.example", Script::rcpt("bob@remote.example", full));
	pass_on_day(&worker, start, 3).await;
	pass_on_day(&worker, start, 4).await;
	remote.script("remote.example", Script::default());
	pass_on_day(&worker, start, 5).await;

	assert_eq!(
		outcomes(dir.path()),
		vec![
			(Deferred, Some(busy.to_string()), 1),
			(Deferred, Some(full.to_string()), 4),
			(Delivered, Some("250 2.0.0 queued".to_string()), 6),
		]
	);
}

#[tokio::test]
async fn a_remote_that_words_every_deferral_differently_cannot_flood_the_log() {
	use crate::storage::DeliveryOutcome::Deferred;
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let start = 1_700_000_000;
	let worker = retrying_worker(dir.path(), &remote, start);

	for day in 0..30 {
		let reply = format!("450 4.2.1 busy, session {day}");
		remote.script("remote.example", Script::rcpt("bob@remote.example", &reply));
		pass_on_day(&worker, start, day).await;
	}

	let deferred: Vec<u32> = outcomes(dir.path())
		.into_iter()
		.filter(|(outcome, _, _)| *outcome == Deferred)
		.map(|(_, _, attempt)| attempt)
		.collect();
	assert_eq!(deferred, (1..=8).collect::<Vec<u32>>());
	let id = worker.spool.list().expect("list")[0];
	let state = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state("bob@remote.example");
	assert_eq!(state.attempts, 30, "every attempt still counts");
}
