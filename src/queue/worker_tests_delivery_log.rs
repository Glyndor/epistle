//! The delivery worker writes a metadata-only record for every recipient
//! outcome into the on-disk delivery log.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::queue::SuppressionList;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use crate::storage::delivery_log::DeliveryLog;

fn spool_with(dir: &std::path::Path, message: &AcceptedMessage) -> FsSpool {
	let spool = FsSpool::open(dir).expect("spool");
	spool.store(message, None, &BTreeMap::new()).expect("store");
	spool
}

fn load_records(dir: &std::path::Path) -> Vec<crate::storage::DeliveryRecord> {
	let mut records = Vec::new();
	let root = dir.join("deliverylog");
	let Ok(entries) = std::fs::read_dir(&root) else {
		return records;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
			continue;
		}
		let Ok(text) = std::fs::read_to_string(&path) else {
			continue;
		};
		for line in text.lines() {
			if line.is_empty() {
				continue;
			}
			records.push(serde_json::from_str(line).expect("record"));
		}
	}
	records
}

#[tokio::test]
async fn a_delivered_recipient_writes_a_record_with_the_remote_host() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with(
		dir.path(),
		&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["bob@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		},
	);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("bob@remote.example", "250 OK"),
	);
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.pass().await.expect("pass");

	let records = load_records(dir.path());
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].recipient, "bob@remote.example");
	assert_eq!(
		records[0].outcome,
		crate::storage::DeliveryOutcome::Delivered
	);
	assert_eq!(records[0].remote.as_deref(), Some("mx.remote.example"));
	assert_eq!(records[0].reply.as_deref(), Some("250 OK"));
	assert_eq!(records[0].from, "alice@sender.example");
}

#[tokio::test]
async fn a_transient_failure_writes_a_deferred_record_with_the_reply() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with(
		dir.path(),
		&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["bob@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		},
	);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("bob@remote.example", "450 4.2.1 mailbox busy, try later"),
	);
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.pass().await.expect("pass");

	let records = load_records(dir.path());
	assert_eq!(records.len(), 1);
	assert_eq!(
		records[0].outcome,
		crate::storage::DeliveryOutcome::Deferred
	);
	assert_eq!(records[0].remote.as_deref(), Some("mx.remote.example"));
	assert_eq!(
		records[0].reply.as_deref(),
		Some("450 4.2.1 mailbox busy, try later")
	);
}

#[tokio::test]
async fn a_permanent_failure_writes_a_failed_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with(
		dir.path(),
		&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["bob@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		},
	);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("bob@remote.example", "550 5.1.1 user unknown"),
	);
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.pass().await.expect("pass");

	let records = load_records(dir.path());
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].outcome, crate::storage::DeliveryOutcome::Failed);
	assert_eq!(records[0].reply.as_deref(), Some("550 5.1.1 user unknown"));
}

#[tokio::test]
async fn a_suppressed_recipient_writes_a_record_with_no_remote() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["bob@suppressed.example".into()],
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
	let suppression = SuppressionList::open(dir.path()).expect("suppression");
	suppression.suppress("bob@suppressed.example");
	let worker = Worker::new(
		spool,
		Arc::new(FakeRemote::default()),
		"mail.sender.example",
	)
	.with_suppression(suppression)
	.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.pass().await.expect("pass");

	let records = load_records(dir.path());
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].recipient, "bob@suppressed.example");
	assert_eq!(
		records[0].outcome,
		crate::storage::DeliveryOutcome::Suppressed
	);
	assert!(records[0].remote.is_none());
}

#[tokio::test]
async fn a_disabled_log_writes_no_records() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with(
		dir.path(),
		&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["bob@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		},
	);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("bob@remote.example", "250 OK"),
	);
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_delivery_log(DeliveryLog::open(dir.path(), 0));
	worker.pass().await.expect("pass");
	assert!(load_records(dir.path()).is_empty());
	assert!(!dir.path().join("deliverylog").exists());
}

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
			(Delivered, Some("250 OK".to_string()), 6),
		]
	);
}
