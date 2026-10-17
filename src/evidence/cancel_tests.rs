use std::collections::BTreeMap;

use super::*;
use crate::evidence::MailClass;
use crate::evidence::record::{Entry, OutcomeKind};
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
	// By place in the chain: a day is read again after each break gone past.
	let mut found = std::collections::BTreeMap::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		crate::evidence::ack::walk_day_acknowledged(&root, day, |line, record, _| {
			if let Entry::Outcome(outcome) = &record.entry
				&& outcome.result == OutcomeKind::Canceled
			{
				found.insert((day, line), outcome.recipient.clone());
			}
		})
		.expect("walk");
	}
	let mut found: Vec<String> = found.into_values().collect();
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

/// Run `remove` with the writing failing at the record `at`.
fn remove_failing(
	spool: &FsSpool,
	dir: &Path,
	id: uuid::Uuid,
	at: usize,
	how: Fail,
) -> std::io::Error {
	FAIL_AT.with(|fail| fail.set(Some((at, how))));
	let error = remove(spool, &crate::evidence::service::root_of(dir), id).expect_err("fails");
	FAIL_AT.with(|fail| fail.set(None));
	error
}

#[test]
fn a_cancellation_cut_short_keeps_the_entry_on_hold_and_the_retry_writes_nothing_twice() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	// The first recipient's cancellation is written, the second's is refused.
	let error = remove_failing(&spool, dir.path(), id, 1, Fail::Clean);
	assert!(error.to_string().contains("injected"), "{error}");
	assert_eq!(canceled(dir.path()), vec!["a@remote.example".to_string()]);
	assert!(
		spool
			.load_envelope(id)
			.expect("the entry stays")
			.held
			.is_some(),
		"the worker would deliver what was recorded as canceled"
	);
	// Once the writing works, the removal is finished, with each recipient
	// canceled exactly once.
	remove(&spool, &crate::evidence::service::root_of(dir.path()), id).expect("removed");
	assert!(spool.load_envelope(id).is_err());
	assert_eq!(
		canceled(dir.path()),
		vec![
			"a@remote.example".to_string(),
			"b@remote.example".to_string()
		]
	);
}

#[test]
fn a_cancellation_that_wrote_nothing_gives_the_entry_back_as_it_was() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	remove_failing(&spool, dir.path(), id, 0, Fail::Clean);
	assert!(spool.load_envelope(id).expect("entry").held.is_none());
	assert!(canceled(dir.path()).is_empty());
}

#[test]
fn an_unconfirmed_record_on_the_first_recipient_keeps_the_entry_on_hold() {
	for how in [Fail::WrittenUnconfirmed, Fail::UnwrittenUnconfirmed] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (spool, id) = two_recipients(dir.path());
		let error = remove_failing(&spool, dir.path(), id, 0, how);
		assert!(crate::evidence::chain::Unconfirmed::is(&error), "{error}");
		assert!(
			spool
				.load_envelope(id)
				.expect("the entry stays")
				.held
				.is_some(),
			"{how:?}: a record that may exist was left beside a live entry"
		);
		remove(&spool, &crate::evidence::service::root_of(dir.path()), id).expect("retried");
		// Whether or not the first record was there, it is there once.
		assert_eq!(
			canceled(dir.path()),
			vec![
				"a@remote.example".to_string(),
				"b@remote.example".to_string()
			],
			"{how:?}"
		);
		assert!(spool.load_envelope(id).is_err());
	}
}

#[test]
fn an_unconfirmed_record_on_the_second_recipient_keeps_the_entry_on_hold() {
	for how in [Fail::WrittenUnconfirmed, Fail::UnwrittenUnconfirmed] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (spool, id) = two_recipients(dir.path());
		let error = remove_failing(&spool, dir.path(), id, 1, how);
		assert!(crate::evidence::chain::Unconfirmed::is(&error), "{error}");
		assert!(
			spool.load_envelope(id).expect("entry").held.is_some(),
			"{how:?}"
		);
		remove(&spool, &crate::evidence::service::root_of(dir.path()), id).expect("retried");
		assert_eq!(
			canceled(dir.path()),
			vec![
				"a@remote.example".to_string(),
				"b@remote.example".to_string()
			],
			"{how:?}"
		);
	}
}

#[test]
fn an_entry_an_operator_held_long_ago_is_removed_without_reading_the_chain_from_then() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (spool, id) = two_recipients(dir.path());
	let long_ago = crate::storage::delivery_log::now_epoch() - 30 * 86_400;
	spool
		.update_envelope(id, |envelope| envelope.hold(long_ago))
		.expect("held by hand");
	// A day since then that cannot be read: the removal does not go there.
	let root = crate::evidence::service::root_of(dir.path());
	let old = crate::evidence::day::Day::of_epoch(long_ago + 86_400);
	Chain::open(&root)
		.expect("chain")
		.append(crate::evidence::test_support::accepted(50))
		.expect("a record of today");
	std::fs::write(
		root.join("chain").join(format!("{}.jsonl", old.name())),
		b"not a record\n",
	)
	.expect("unreadable day");
	remove(&spool, &root, id).expect("removed");
	assert!(spool.load_envelope(id).is_err());
}

#[test]
fn a_removal_cut_short_goes_on_though_a_break_in_the_chain_was_acknowledged() {
	use crate::evidence::ack::{Operator, acknowledge_at};
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	let now = crate::storage::delivery_log::now_epoch();
	let chain = Chain::open(&root).expect("chain");
	for n in 0..3 {
		chain
			.append(crate::evidence::test_support::accepted(40 + n))
			.expect("record");
	}
	let file = chain.day_file(crate::evidence::day::Day::of_epoch(now));
	let text = std::fs::read_to_string(&file).expect("day");
	let lines: Vec<&str> = text.lines().collect();
	std::fs::write(&file, format!("{}\n{}\n", lines[0], lines[2])).expect("cut a line");
	let first = crate::evidence::audit::verify(
		&root,
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: Vec::new(),
			now,
		},
	)
	.expect("verify")
	.first_break
	.expect("a break");
	let key = crate::evidence::key::EvidenceKey::load_or_create(&root).expect("key");
	acknowledge_at(
		&root,
		&key,
		&first,
		"test",
		&Operator::named("uid=0 sudo_user=a host=h"),
		now,
	)
	.expect("ack");
	let (spool, id) = two_recipients(dir.path());
	remove_failing(&spool, dir.path(), id, 1, Fail::Clean);
	remove(&spool, &root, id).expect("the retry goes past the acknowledged break");
	assert_eq!(
		canceled(dir.path()),
		vec![
			"a@remote.example".to_string(),
			"b@remote.example".to_string()
		]
	);
}
