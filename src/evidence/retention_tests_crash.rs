//! A purge that is cut short is finished, once, from any step.

use super::tests::{DAY, stamp_all, verified};
use super::*;
use crate::evidence::test_support::{accepted_for, at};
use crate::evidence::tsa::fake::FakeTsa;

/// Four days kept two, sealed and stamped, and the time the first three can go.
fn old_days() -> (tempfile::TempDir, EvidenceKey, FakeTsa, u64) {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let mut tsa = FakeTsa::new(at(DAY + 30, 0));
	let chain = Chain::open(dir.path()).expect("chain");
	for offset in 0..4 {
		chain
			.append_at(at(DAY + offset, 1), accepted_for(offset as u32, 2))
			.expect("append");
	}
	stamp_all(dir.path(), &key, &mut tsa, at(DAY + 4, 0));
	(dir, key, tsa, at(DAY + 5, 12))
}

fn purge_records(root: &Path) -> usize {
	let mut found = 0;
	for day in Chain::open(root).expect("chain").days().expect("days") {
		crate::evidence::verify::walk_day(root, day, None, |_, record, _| {
			found += usize::from(matches!(record.entry, Entry::Purge(_)));
		})
		.expect("walk");
	}
	found
}

#[test]
fn a_purge_cut_short_at_any_step_is_finished_once_and_the_chain_verifies() {
	for cut_at in [Step::Statement, Step::Recorded, Step::Anchored] {
		let (dir, key, mut tsa, now) = old_days();
		sweep_steps(dir.path(), &key, &[tsa.anchor], now, |step| step == cut_at)
			.expect_err("cut short");
		let swept = sweep(dir.path(), &key, &[tsa.anchor], now + 300).expect("the next sweep");
		assert!(swept.refused.is_none(), "{cut_at:?}: {:?}", swept.refused);
		// Whatever the cut, the days went, once, with one statement.
		let chain = Chain::open(dir.path()).expect("chain");
		assert!(
			chain
				.days()
				.expect("days")
				.iter()
				.all(|day| *day >= Day(DAY + 3)),
			"{cut_at:?}: purged days are still there"
		);
		let later = at(DAY + 7, 0);
		chain
			.append_at(at(DAY + 6, 1), accepted_for(9, 2))
			.expect("append after");
		stamp_all(dir.path(), &key, &mut tsa, later);
		let report = verified(dir.path(), &tsa, later);
		assert_eq!(
			report.first_break.as_ref().map(ToString::to_string),
			None,
			"{cut_at:?}"
		);
		let statements = std::fs::read_dir(dir.path().join(PURGES_DIR))
			.expect("dir")
			.count();
		assert_eq!(statements, 2, "{cut_at:?}: one statement and its signature");
		assert_eq!(purge_records(dir.path()), 1, "{cut_at:?}");
	}
}

#[test]
fn a_statement_the_chain_never_named_is_dropped_and_the_purge_decided_again() {
	let (dir, key, tsa, now) = old_days();
	sweep_steps(dir.path(), &key, &[tsa.anchor], now, |step| {
		step == Step::Statement
	})
	.expect_err("cut short");
	assert_eq!(purge_records(dir.path()), 0, "nothing was recorded");
	let swept = sweep(dir.path(), &key, &[tsa.anchor], now + 300).expect("the next sweep");
	assert_eq!(swept.days, 3, "the days are purged by a fresh decision");
	assert_eq!(purge_records(dir.path()), 1);
}
