//! Taking a message that kept evidence out of the queue leaves a record.

use super::base::spool_with;
use super::*;
use crate::cli::queue::QueueCli;
use crate::evidence::MailClass;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Entry, OutcomeKind};

fn keep_evidence(spool: &FsSpool, id: Uuid) {
	spool
		.update_envelope(id, |envelope| {
			envelope.evidence = true;
			envelope.class = MailClass::Transactional;
			envelope.retain_days = 365;
		})
		.expect("evidence");
}

fn outcomes(dir: &Path) -> Vec<(String, OutcomeKind)> {
	let root = crate::evidence::service::root_of(dir);
	let mut found = Vec::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		crate::evidence::verify::walk_day(&root, day, None, |_, record, _| {
			if let Entry::Outcome(outcome) = &record.entry {
				found.push((outcome.recipient.clone(), outcome.result));
			}
		})
		.expect("walk");
	}
	found
}

fn remove(dir: &Path, id: Uuid) -> ExitCode {
	run(
		dir,
		None,
		30,
		Some(QueueCli::Remove { id, yes: true }),
		false,
		1_700_000_000,
		None,
		&mut Vec::new(),
	)
}

#[test]
fn removing_a_message_that_kept_evidence_records_its_cancellation() {
	let (dir, spool, ids) = spool_with(1);
	keep_evidence(&spool, ids[0]);
	assert_eq!(remove(dir.path(), ids[0]), ExitCode::SUCCESS);
	assert_eq!(
		outcomes(dir.path()),
		vec![("bob0@remote.example".to_string(), OutcomeKind::Canceled)]
	);
	assert!(spool.list().expect("list").is_empty());
}

#[test]
fn a_message_that_kept_no_evidence_leaves_none() {
	let (dir, spool, ids) = spool_with(1);
	assert_eq!(remove(dir.path(), ids[0]), ExitCode::SUCCESS);
	assert!(outcomes(dir.path()).is_empty());
	assert!(spool.list().expect("list").is_empty());
}

#[test]
fn an_entry_the_evidence_log_is_still_owed_stays_and_records_nothing() {
	let (dir, spool, ids) = spool_with(1);
	keep_evidence(&spool, ids[0]);
	spool
		.update_envelope(ids[0], |envelope| {
			envelope
				.outcomes_pending
				.push(crate::storage::PendingOutcome {
					recipient: "bob0@remote.example".into(),
					result: OutcomeKind::Delivered,
					attempt: 1,
					remote: None,
					reply: None,
					tls: None,
					dane: false,
					mta_sts: None,
				});
		})
		.expect("pending");
	assert_ne!(remove(dir.path(), ids[0]), ExitCode::SUCCESS);
	assert!(outcomes(dir.path()).is_empty());
	assert_eq!(spool.list().expect("list").len(), 1);
}

#[test]
fn an_entry_whose_cancellation_cannot_be_recorded_is_not_removed() {
	let (dir, spool, ids) = spool_with(1);
	keep_evidence(&spool, ids[0]);
	// The log cannot take a record: today's day file is a directory.
	let day = crate::evidence::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	std::fs::create_dir_all(
		dir.path()
			.join("evidence/chain")
			.join(format!("{}.jsonl", day.name())),
	)
	.expect("block");
	assert_ne!(remove(dir.path(), ids[0]), ExitCode::SUCCESS);
	assert_eq!(spool.list().expect("list").len(), 1, "the entry went");
}
