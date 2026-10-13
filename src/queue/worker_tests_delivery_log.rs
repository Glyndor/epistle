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
	spool
		.store(message, None, &BTreeMap::new())
		.expect("store");
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
	assert_eq!(records[0].outcome, crate::storage::DeliveryOutcome::Delivered);
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
	assert_eq!(records[0].outcome, crate::storage::DeliveryOutcome::Deferred);
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
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let suppression = SuppressionList::open(dir.path()).expect("suppression");
	suppression.suppress("bob@suppressed.example");
	let worker = Worker::new(spool, Arc::new(FakeRemote::default()), "mail.sender.example")
		.with_suppression(suppression)
		.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.pass().await.expect("pass");

	let records = load_records(dir.path());
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].recipient, "bob@suppressed.example");
	assert_eq!(records[0].outcome, crate::storage::DeliveryOutcome::Suppressed);
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
			no_dsn: Vec::new(),
		},
	);
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::rcpt("bob@remote.example", "250 OK"));
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_delivery_log(DeliveryLog::open(dir.path(), 0));
	worker.pass().await.expect("pass");
	assert!(load_records(dir.path()).is_empty());
	assert!(!dir.path().join("deliverylog").exists());
}
