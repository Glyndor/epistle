use super::*;
use crate::evidence::test_support::{accepted, at, delivered};

const DAY: i64 = 20_740;

/// A data directory whose evidence holds message 1 (one recipient) accepted
/// at the start of a day.
fn orphan() -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 1), accepted(1))
		.expect("accepted");
	(dir, root)
}

fn id() -> Uuid {
	Uuid::from_u128(1)
}

#[test]
fn what_the_chain_gained_since_the_operator_looked_is_seen_before_writing() {
	let (dir, root) = orphan();
	let now = at(DAY, 5);
	// What the operator was shown: nothing has an ending.
	assert!(to_close(&told(&root, id()).expect("told"), now).is_ok());
	// Then the worker delivered, and wrote its outcome.
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 2), delivered(1))
		.expect("outcome");
	let closed = close(dir.path(), (&root, id()), "closed by test: late", now).expect("closing");
	assert!(matches!(closed, Err(Refusal::NothingPending)));
	let chain = Chain::open(&root).expect("chain");
	let mut abandoned = 0;
	for day in chain.days().expect("days") {
		crate::evidence::verify::walk_day(&root, day, None, |_, record, _| {
			abandoned += usize::from(matches!(record.entry, Entry::Abandoned(_)));
		})
		.expect("walk");
	}
	assert_eq!(abandoned, 0, "a delivered message was marked abandoned");
}

#[test]
fn an_acceptance_too_young_is_not_closed() {
	let (dir, root) = orphan();
	let closed = close(
		dir.path(),
		(&root, id()),
		"closed by test: early",
		at(DAY, 1) + 30,
	)
	.expect("closing");
	assert!(matches!(closed, Err(Refusal::TooRecent)));
}

#[test]
fn an_old_orphan_is_closed_and_then_has_nothing_pending() {
	let (dir, root) = orphan();
	let now = at(DAY, 5);
	let closed = close(dir.path(), (&root, id()), "closed by test: gone", now).expect("closing");
	assert!(closed.is_ok());
	assert!(told(&root, id()).expect("told").pending().is_empty());
}
