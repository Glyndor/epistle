use std::collections::BTreeMap;

use super::*;
use crate::evidence::MailClass;
use crate::evidence::record::{Entry, OutcomeKind};
use crate::evidence::verify::walk_day;
use crate::smtp::session::AcceptedMessage;
use crate::storage::{FsSpool, RecipientState, StoreOptions};

/// An entry for two recipients that keeps evidence.
fn two_recipients(dir: &Path) -> (FsSpool, uuid::Uuid) {
	let spool = FsSpool::open(dir).expect("spool");
	let id = uuid::Uuid::now_v7();
	let recorded = |_: &[u8]| Ok(());
	spool
		.store_with(
			&AcceptedMessage {
				reverse_path: "notices@example.org".into(),
				recipients: vec!["a@remote.example".into(), "b@remote.example".into()],
				data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: true,
				no_dsn: Vec::new(),
			},
			id,
			&StoreOptions {
				account: Some("notices"),
				extra: &BTreeMap::new(),
				class: MailClass::Transactional,
				evidence: Some(&recorded as &dyn Fn(&[u8]) -> std::io::Result<()>),
				retain_days: 365,
			},
		)
		.expect("store");
	(spool, id)
}

fn canceled(dir: &Path) -> Vec<String> {
	let root = crate::evidence::service::root_of(dir);
	let mut found = Vec::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		walk_day(&root, day, None, |_, record, _| {
			if let Entry::Outcome(outcome) = &record.entry
				&& outcome.result == OutcomeKind::Canceled
			{
				found.push(outcome.recipient.clone());
			}
		})
		.expect("walk");
	}
	found.sort();
	found
}

#[test]
fn only_the_recipients_still_waiting_when_the_entry_is_removed_are_canceled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	// What the operator was shown: both waiting. Then the worker delivered
	// to one of them before the removal.
	let shown = spool.load_envelope(id).expect("envelope");
	assert_eq!(shown.recipients.len(), 2);
	spool
		.update_envelope(id, |envelope| {
			envelope.set_recipient_state(
				"a@remote.example",
				RecipientState {
					status: RecipientStatus::Delivered,
					..RecipientState::default()
				},
			);
		})
		.expect("delivered meanwhile");
	let removed =
		remove(&spool, &crate::evidence::service::root_of(dir.path()), id).expect("removed");
	assert_eq!(
		removed.recipient_state("a@remote.example").status,
		RecipientStatus::Delivered
	);
	assert_eq!(
		canceled(dir.path()),
		vec!["b@remote.example".to_string()],
		"the recipient that was delivered was canceled from a stale view"
	);
}

#[test]
fn an_outcome_marked_owed_after_the_operator_looked_stops_the_removal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	spool
		.update_envelope(id, |envelope| {
			envelope
				.outcomes_pending
				.push(crate::storage::PendingOutcome {
					recipient: "a@remote.example".into(),
					result: OutcomeKind::Delivered,
					attempt: 1,
					remote: None,
					reply: None,
					tls: None,
					dane: false,
					mta_sts: None,
				});
		})
		.expect("owed");
	let error = remove(&spool, &crate::evidence::service::root_of(dir.path()), id)
		.expect_err("the entry is owed an outcome");
	assert_eq!(error.kind(), std::io::ErrorKind::ResourceBusy);
	assert!(canceled(dir.path()).is_empty());
	assert!(spool.load_envelope(id).is_ok());
}

#[test]
fn nothing_is_removed_when_the_cancellation_cannot_be_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	let day = crate::evidence::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	std::fs::create_dir_all(
		dir.path()
			.join("evidence/chain")
			.join(format!("{}.jsonl", day.name())),
	)
	.expect("block");
	remove(&spool, &crate::evidence::service::root_of(dir.path()), id)
		.expect_err("the record is refused");
	assert!(spool.load_envelope(id).is_ok(), "the entry went");
}

#[test]
fn a_cancellation_is_counted_to_the_account_that_sent_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	let root = crate::evidence::service::root_of(dir.path());
	remove(&spool, &root, id).expect("removed");
	let quota =
		crate::evidence::quota::Quota::open(&root, crate::evidence::quota::Limits::default());
	assert_eq!(quota.state().accounts["notices"].records, 2);
}
