//! Unit tests for the per-account junk trainer hook.
//!
//! The transition table is the one place the spam/ham decision lives,
//! so it gets a single table-driven control. Every row names the
//! change and the expected `JunkSignal`; the helper is called with
//! fresh flags each run, and the trainer is invoked through the
//! real `TrainingQueue` worker so the trainer sees the bytes the
//! worker read off disk.

use std::path::PathBuf;
use std::sync::Arc;

use super::{JunkSignal, enqueue_junk_transition, junk_signal};
use crate::antispam::trainer::RecordingTrainer;
use crate::imap::keyword::{JUNK, NOT_JUNK};
use crate::imap::mailbox::Flag;

/// Parse the canonical reserved keyword tokens.
fn junk() -> Flag {
	Flag::parse(JUNK).expect("parse $Junk")
}

fn not_junk() -> Flag {
	Flag::parse(NOT_JUNK).expect("parse $NotJunk")
}

/// The transition table the production path consults. Each row holds
/// the helper input as raw flag tokens and the expected
/// [`JunkSignal`].
type JunkCase = (&'static str, Vec<Flag>, Vec<Flag>, Option<JunkSignal>);

#[test]
fn junk_signal_table() {
	let j = junk();
	let nj = not_junk();
	let j_lower = Flag::parse("$junk").expect("parse $junk");
	let cases: [JunkCase; 7] = [
		(
			"add $Junk",
			Vec::new(),
			vec![j.clone()],
			Some(JunkSignal::Spam),
		),
		(
			"add $NotJunk",
			Vec::new(),
			vec![nj.clone()],
			Some(JunkSignal::Ham),
		),
		(
			"remove $Junk, $NotJunk not added",
			vec![j.clone()],
			Vec::new(),
			Some(JunkSignal::Ham),
		),
		("remove $NotJunk alone", vec![nj.clone()], Vec::new(), None),
		(
			"add both at once",
			Vec::new(),
			vec![j.clone(), nj.clone()],
			None,
		),
		(
			"neither keyword changes",
			vec![Flag::Seen],
			vec![Flag::Seen, Flag::Flagged],
			None,
		),
		(
			"$junk replaces $Junk case-only",
			vec![j.clone()],
			vec![j_lower],
			None,
		),
	];
	for (label, previous, updated, expected) in &cases {
		let signal = junk_signal(previous, updated);
		assert_eq!(signal, *expected, "{label}: signal mismatch");
	}
}

/// `enqueue_junk_transition` only submits a job when the helper's
/// signal column is `Some`. The trainer is reached only after the
/// worker drains the job; the helper itself never invokes it.
#[test]
fn enqueue_submits_a_job_only_when_there_is_a_signal() {
	let j = junk();
	let nj = not_junk();
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let (queue, _receiver) = crate::antispam::training_queue::TrainingQueue::bounded(8, metrics);
	let path = PathBuf::from("/dev/null");
	assert!(
		enqueue_junk_transition(&queue, "alice", &[], std::slice::from_ref(&j), path.clone()),
		"add $Junk submits"
	);
	assert!(
		enqueue_junk_transition(
			&queue,
			"alice",
			&[],
			std::slice::from_ref(&nj),
			path.clone()
		),
		"add $NotJunk submits"
	);
	assert!(
		enqueue_junk_transition(&queue, "alice", std::slice::from_ref(&j), &[], path.clone()),
		"remove $Junk submits"
	);
	assert!(
		!enqueue_junk_transition(
			&queue,
			"alice",
			std::slice::from_ref(&nj),
			&[],
			path.clone()
		),
		"remove $NotJunk alone: nothing to teach"
	);
	assert!(
		!enqueue_junk_transition(&queue, "alice", &[], &[j, nj], path.clone()),
		"both added: contradictory, nothing to teach"
	);
}

/// The worker that drains the queue reads the message file and
/// passes the bytes to the trainer. A real `RecordingTrainer` driven
/// by a worker task records the bytes it saw, so the queue's path
/// becomes the wire the production path uses.
#[tokio::test]
async fn the_worker_invokes_the_trainer_with_the_message_bytes() {
	use crate::antispam::training_queue::TrainingQueue;
	use crate::storage::MessageCrypto;

	let dir = tempfile::tempdir().expect("tempdir");
	let message_path = dir.path().join("message.eml");
	let body = b"hello world body";
	std::fs::write(&message_path, body).expect("write message");

	let trainer = Arc::new(RecordingTrainer::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let queue = TrainingQueue::start(
		Arc::clone(&trainer) as Arc<dyn crate::antispam::trainer::BayesTrainer>,
		MessageCrypto::disabled(),
		Arc::clone(&metrics),
	);
	let path = message_path.clone();
	assert!(enqueue_junk_transition(
		&queue,
		"alice",
		&[],
		&[junk()],
		path,
	));
	trainer.await_one_call().await;
	let calls = trainer.calls();
	assert_eq!(calls.len(), 1, "one train call recorded: {calls:?}");
	assert_eq!(calls[0].0, "alice");
	assert_eq!(calls[0].1, body.len(), "the trainer saw the message bytes");
	assert!(calls[0].2, "spam side for added $Junk");
}
