//! An acknowledgement covers the break it was made for, in the state it
//! was made for, and no other.

use crate::evidence::ack::{Operator, acknowledge_at};
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::audit::{Options, Report, verify};
use crate::evidence::chain::Chain;
use crate::evidence::day::Day;
use crate::evidence::test_support::{accepted, at, delivered};

fn run(fixture: &Fixture, now: u64) -> Report {
	verify(
		fixture.root(),
		&Options {
			from: None,
			to: None,
			anchors: vec![fixture.tsa.anchor],
			now,
		},
	)
	.expect("verify")
}

/// Append a record on `DAY + 3` and cut it away again: the chain ends
/// before the head.
fn roll_back(fixture: &Fixture, hour: u64, n: u32) {
	let chain = Chain::open(fixture.root()).expect("chain");
	let path = chain.day_file(Day(DAY + 3));
	let kept = std::fs::read(&path).unwrap_or_default();
	chain
		.append_at(at(DAY + 3, hour), delivered(n))
		.expect("append");
	if kept.is_empty() {
		std::fs::remove_file(&path).expect("remove");
	} else {
		std::fs::write(&path, kept).expect("truncate");
	}
}

fn acknowledge(fixture: &Fixture, found: &crate::evidence::verify::Break, hour: u64) {
	acknowledge_at(
		fixture.root(),
		&fixture.key,
		found,
		"restored from backup",
		&Operator::named("uid=0 host=mail"),
		at(DAY + 3, hour),
	)
	.expect("acknowledge");
}

#[test]
fn acknowledging_a_rollback_does_not_cover_a_later_one() {
	let fixture = Fixture::new();
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	roll_back(&fixture, 2, 7);
	let first = run(&fixture, at(DAY + 3, 5))
		.first_break
		.expect("a rollback");
	assert!(first.to_string().contains("rollback"), "{first}");
	acknowledge(&fixture, &first, 6);
	let after = run(&fixture, at(DAY + 3, 7));
	assert_eq!(after.first_break, None, "{:?}", after.first_break);
	// The chain is rolled back again, to another state.
	roll_back(&fixture, 8, 8);
	let second = run(&fixture, at(DAY + 3, 9))
		.first_break
		.expect("the second rollback is not covered by the first acknowledgement");
	assert!(second.to_string().contains("rollback"), "{second}");
	assert_ne!(second.to_string(), first.to_string(), "the same identity");
}

fn bogus_hand_over(n: u8, fixture: &Fixture) -> crate::evidence::record::Entry {
	crate::evidence::record::Entry::KeyRotated(crate::evidence::rotation::Rotation {
		old: fixture.key.id(),
		new: format!("{n:02x}").repeat(32),
		day: Day(DAY + 3).name(),
		signature: "cd".repeat(64),
	})
}

#[test]
fn acknowledging_a_break_in_one_record_does_not_cover_the_same_break_in_another() {
	let fixture = Fixture::new();
	let chain = Chain::open(fixture.root()).expect("chain");
	chain
		.append_at(at(DAY + 3, 1), bogus_hand_over(1, &fixture))
		.expect("first");
	chain
		.append_at(at(DAY + 3, 2), bogus_hand_over(2, &fixture))
		.expect("second");
	let first = run(&fixture, at(DAY + 3, 5)).first_break.expect("a break");
	assert!(first.to_string().contains("line 1"), "the line: {first}");
	acknowledge(&fixture, &first, 6);
	let after = run(&fixture, at(DAY + 3, 7));
	let second = after
		.first_break
		.expect("the other record is not covered by the acknowledgement");
	assert!(second.to_string().contains("line 2"), "{second}");
	assert_eq!(after.acknowledged, vec![first]);
}

#[test]
fn acknowledging_a_purge_anchor_failure_does_not_cover_another_anchor() {
	use crate::evidence::checkpoint::load;
	use crate::evidence::record::{Position, hash_from_hex, sha256};
	let fixture = Fixture::new();
	let write_anchor = |offset: i64, checkpoint: Option<[u8; 32]>| {
		let (cp, bytes) = load(fixture.root(), Day(DAY + offset))
			.expect("load")
			.expect("cp");
		crate::evidence::anchor::write(
			&fixture.root().join(crate::evidence::chain::CHAIN_DIR),
			&Day(DAY + offset).name(),
			&Position {
				hash: hash_from_hex(&cp.last_hash).expect("hash"),
				seq: cp.last_seq,
				time: cp.last_time,
			},
			&checkpoint.unwrap_or_else(|| sha256(&bytes)),
		)
		.expect("anchor");
	};
	// An anchor with no purge record behind it, the days kept as they are.
	write_anchor(0, None);
	let first = run(&fixture, at(DAY + 3, 5)).first_break.expect("a break");
	assert!(
		first.to_string().contains("purged without a purge record"),
		"{first}"
	);
	acknowledge(&fixture, &first, 6);
	assert_eq!(run(&fixture, at(DAY + 3, 7)).first_break, None);
	// The same anchor with another checkpoint hash: another state of the same break.
	write_anchor(0, Some(sha256(b"another checkpoint")));
	let second = run(&fixture, at(DAY + 3, 8))
		.first_break
		.expect("a different anchor is not covered by the earlier acknowledgement");
	assert_ne!(second.to_string(), first.to_string());
}
