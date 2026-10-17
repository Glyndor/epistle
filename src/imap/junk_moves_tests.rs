//! The move table and the cap on lessons per command. No database.

use std::sync::Arc;

use super::{enqueue_move, move_signal};
use crate::antispam::training_queue::{LessonBudget, MAX_PENDING_PER_ACCOUNT, TrainingQueue};
use crate::imap::junk_trainer::JunkSignal;
use crate::metrics::Metrics;

type Case = (
	&'static str,
	&'static str,
	&'static str,
	bool,
	Option<JunkSignal>,
);

#[test]
fn move_signal_table() {
	let cases: [Case; 14] = [
		(
			"copy into Junk",
			"INBOX",
			"Junk",
			false,
			Some(JunkSignal::Spam),
		),
		(
			"move into Junk",
			"INBOX",
			"Junk",
			true,
			Some(JunkSignal::Spam),
		),
		(
			"move into Rejects",
			"Archive",
			"Rejects",
			true,
			Some(JunkSignal::Spam),
		),
		(
			"trash back into Junk",
			"Trash",
			"Junk",
			true,
			Some(JunkSignal::Spam),
		),
		(
			"move out to INBOX",
			"Junk",
			"INBOX",
			true,
			Some(JunkSignal::Ham),
		),
		(
			"move out to Archive",
			"Junk",
			"Archive",
			true,
			Some(JunkSignal::Ham),
		),
		(
			"move out to a custom folder",
			"Rejects",
			"Projects/Mail",
			true,
			Some(JunkSignal::Ham),
		),
		(
			"move out to lowercase inbox path",
			"Junk",
			"inbox/Work",
			true,
			Some(JunkSignal::Ham),
		),
		("copy out of Junk", "Junk", "INBOX", false, None),
		("move out to Trash", "Junk", "Trash", true, None),
		("Junk onto itself", "Junk", "junk", true, None),
		("between ordinary mailboxes", "INBOX", "Archive", true, None),
		(
			"a folder that only ends in Junk",
			"INBOX",
			"Archive/Junk",
			true,
			None,
		),
		(
			"out of a folder that only ends in Junk",
			"Archive/Junk",
			"INBOX",
			true,
			None,
		),
	];
	for (label, source, target, removes, expected) in cases {
		assert_eq!(
			move_signal(source, target, removes),
			expected,
			"{label}: {source} to {target}"
		);
	}
}

#[test]
fn a_move_of_ten_thousand_messages_queues_a_bounded_batch_and_counts_the_rest() {
	let metrics = Arc::new(Metrics::new());
	let (queue, mut receiver) = TrainingQueue::bounded(256, Arc::clone(&metrics));
	let dir = tempfile::tempdir().expect("tempdir");
	let ids: Vec<uuid::Uuid> = (0..10_000).map(|_| uuid::Uuid::now_v7()).collect();
	let start = std::time::Instant::now();
	let queued = enqueue_move(
		&queue,
		"alice",
		JunkSignal::Ham,
		dir.path(),
		&ids,
		&mut LessonBudget::new(),
	);
	assert_eq!(
		queued, MAX_PENDING_PER_ACCOUNT,
		"one account has at most its share of the queue waiting"
	);
	assert!(
		start.elapsed() < std::time::Duration::from_millis(500),
		"queueing never waits for the worker"
	);
	let mut jobs = Vec::new();
	while let Ok(job) = receiver.try_recv() {
		jobs.push(job);
	}
	assert_eq!(jobs.len(), MAX_PENDING_PER_ACCOUNT);
	assert!(jobs.iter().all(|job| !job.spam && job.account == "alice"));
	assert_eq!(
		jobs[0].path,
		dir.path().join(format!("{}.eml", ids[0])),
		"the job names the stored file"
	);
	let dropped = 10_000 - u64::try_from(MAX_PENDING_PER_ACCOUNT).expect("share fits");
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(dropped),
		"every message past the cap is counted as dropped"
	);
}

#[test]
fn a_commands_budget_caps_its_lessons_across_calls_and_counts_the_rest() {
	let metrics = Arc::new(Metrics::new());
	let (queue, mut receiver) = TrainingQueue::bounded(256, Arc::clone(&metrics));
	let queue = queue.with_command_lessons(3);
	let dir = tempfile::tempdir().expect("tempdir");
	// A command that calls once per message, as a JMAP Email/set does.
	let mut budget = queue.command_budget();
	let queued: usize = (0..10)
		.map(|_| {
			let id = uuid::Uuid::now_v7();
			enqueue_move(
				&queue,
				"alice",
				JunkSignal::Spam,
				dir.path(),
				&[id],
				&mut budget,
			)
		})
		.sum();
	assert_eq!(queued, 3, "three lessons in the budget");
	assert_eq!(receiver.try_recv().iter().count(), 1);
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(7),
		"the other seven are counted"
	);
	// Another command starts with a full budget.
	let mut next = queue.command_budget();
	let id = uuid::Uuid::now_v7();
	assert_eq!(
		enqueue_move(
			&queue,
			"alice",
			JunkSignal::Spam,
			dir.path(),
			&[id],
			&mut next
		),
		1
	);
}
