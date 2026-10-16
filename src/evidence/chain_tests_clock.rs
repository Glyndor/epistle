//! A clock that jumps cannot send a record to a sealed day or a far future.

use super::tests_lines;
use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::test_support::{accepted, at};

#[test]
fn a_record_cannot_be_written_into_a_day_that_is_sealed() {
	let fixture = Fixture::new();
	let chain = Chain::open(fixture.root()).expect("chain");
	let before = std::fs::read(chain.day_file(Day(DAY + 2))).expect("read");
	// The clock went back to the middle of a sealed day.
	let refused = chain
		.append_at(at(DAY + 2, 5), accepted(50))
		.expect_err("a record in a sealed day");
	assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(
		refused.to_string(),
		"the record would fall in 2026-10-16, a day that is already sealed: the clock went back"
	);
	assert_eq!(
		std::fs::read(chain.day_file(Day(DAY + 2))).expect("read"),
		before
	);
	assert_eq!(fixture.verify().first_break, None);
}

#[test]
fn a_clock_far_behind_the_newest_record_is_refused_and_a_small_step_is_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("chain");
	chain
		.append_at(at(DAY + 3, 10), accepted(1))
		.expect("first");
	// An hour and a minute behind: refused, nothing written.
	let behind = at(DAY + 3, 10) - 3660;
	let refused = chain
		.append_at(behind, accepted(2))
		.expect_err("far behind");
	assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(
		refused.to_string(),
		"the clock is more than an hour behind the newest record"
	);
	assert_eq!(tests_lines(&chain, Day(DAY + 3)), 1);
	// A minute behind is a step of the clock: the record keeps the time of the one before.
	chain
		.append_at(at(DAY + 3, 10) - 60, accepted(3))
		.expect("a small step");
	assert_eq!(tests_lines(&chain, Day(DAY + 3)), 2);
}

#[test]
fn a_clock_that_jumps_forward_writes_nothing_and_recovers_when_it_is_right_again() {
	use std::time::{Duration, Instant};
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("chain");
	let start = Instant::now();
	let today = at(DAY + 3, 1);
	chain
		.append_clocked(today, start, accepted(1))
		.expect("first record");
	// Ten seconds later by the monotonic clock, a year later by the wall clock.
	let jumped = today + 365 * 86_400;
	let refused = chain
		.append_clocked(jumped, start + Duration::from_secs(10), accepted(2))
		.expect_err("a jump of a year");
	assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
	assert!(refused.to_string().contains("jumped forward"), "{refused}");
	assert!(
		chain
			.days()
			.expect("days")
			.iter()
			.all(|day| *day == Day::of_epoch(today)),
		"a record went to a day in the future"
	);
	// The clock is put right: a minute after the first record.
	chain
		.append_clocked(today + 60, start + Duration::from_secs(60), accepted(3))
		.expect("the clock is right again");
	// Time that really passed is no jump: a week idle.
	chain
		.append_clocked(
			today + 7 * 86_400,
			start + Duration::from_secs(7 * 86_400),
			accepted(4),
		)
		.expect("a week of uptime");
}
