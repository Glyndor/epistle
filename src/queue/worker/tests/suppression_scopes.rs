//! Which suppressions the worker honours: the sender's own, and only while
//! they last.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::queue::{SuppressionList, SuppressionRules};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use crate::storage::DeliveryOutcome;
use crate::storage::delivery_log::DeliveryLog;

const SENDER: &str = "alice@sender.example";
const TARGET: &str = "bob@remote.example";

fn queue_one(dir: &std::path::Path, sender: &str) -> FsSpool {
	let spool = FsSpool::open(dir).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: sender.into(),
				recipients: vec![TARGET.into()],
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
	spool
}

async fn outcome(dir: &std::path::Path, sender: &str) -> (DeliveryOutcome, usize) {
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::rcpt(TARGET, "250 OK"));
	let worker = Worker::new(
		queue_one(dir, sender),
		Arc::new(remote.clone()),
		"mail.sender.example",
	)
	.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
	.with_suppression(SuppressionList::open(dir).expect("suppression"))
	.with_delivery_log(DeliveryLog::open(dir, 30));
	worker.pass().await.expect("pass");
	let records = super::delivery_log::load_records(dir);
	assert_eq!(records.len(), 1);
	(records[0].outcome, remote.copies(TARGET))
}

#[tokio::test]
async fn a_bounce_of_one_account_stops_that_account_and_not_another() {
	let dir = tempfile::tempdir().expect("tempdir");
	SuppressionList::open(dir.path())
		.expect("suppression")
		.record_bounce(&SuppressionRules::default(), SENDER, TARGET, "550 5.1.1", 1)
		.expect("record");
	assert_eq!(
		outcome(dir.path(), SENDER).await,
		(DeliveryOutcome::Suppressed, 0)
	);
	let other = tempfile::tempdir().expect("tempdir");
	SuppressionList::open(other.path())
		.expect("suppression")
		.record_bounce(&SuppressionRules::default(), SENDER, TARGET, "550 5.1.1", 1)
		.expect("record");
	assert_eq!(
		outcome(other.path(), "carol@sender.example").await,
		(DeliveryOutcome::Delivered, 1),
		"another account of the same server still reaches the address"
	);
}

#[tokio::test]
async fn an_entry_past_its_lifetime_lets_the_address_be_tried_again() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Recorded at the start of 1970 for one day: long over.
	SuppressionList::open(dir.path())
		.expect("suppression")
		.record_bounce(
			&SuppressionRules::default().lasting(1),
			SENDER,
			TARGET,
			"550 5.1.1",
			1,
		)
		.expect("record");
	assert_eq!(
		outcome(dir.path(), SENDER).await,
		(DeliveryOutcome::Delivered, 1)
	);
}
