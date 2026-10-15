//! A clock that jumps must not shut a group's cap for longer than the jump
//! itself would: mail waiting for the cap goes on waking.

use super::tests::{enable, granted};
use super::*;

/// Midnight UTC of the test day.
const MIDNIGHT: u64 = 20_375 * 86_400;
/// The pace of the starting cap of 50 a day.
const INTERVAL: u64 = 1728;

fn on(dir: &Path) -> Warmup {
	enable(dir, |_| {});
	Warmup::open(dir, None, MIDNIGHT)
}

#[test]
fn a_clock_set_back_does_not_shut_the_cap_until_it_catches_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path());
	// The clock runs a year ahead for a moment, and mail goes out then.
	let ahead = MIDNIGHT + 365 * 86_400;
	assert_eq!(granted(warmup.grant(Group::Gmail, "system", 3, ahead)).0, 3);
	// Set right again, the cap opens within one unit of its pace.
	let back = MIDNIGHT + 3600;
	assert_eq!(
		warmup.blocked(Group::Gmail, "system", back),
		Some(back + INTERVAL)
	);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 1, back + INTERVAL)),
		(1, back + INTERVAL)
	);
	let (_, state) = warmup.snapshot();
	assert_eq!(state.day, day_of(back), "the counts belong to today again");
	// And the next day opens on the real clock.
	let tomorrow = MIDNIGHT + 86_400;
	assert_eq!(state.group(Group::Gmail).sent, 4);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 3, tomorrow)).0,
		3
	);
	assert_eq!(warmup.snapshot().1.group(Group::Gmail).sent, 3);
}

#[test]
fn a_clock_set_back_within_the_day_waits_one_unit_at_most() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path());
	let later = MIDNIGHT + 20 * 3600;
	assert_eq!(granted(warmup.grant(Group::Gmail, "system", 3, later)).0, 3);
	let earlier = MIDNIGHT + 3600;
	assert_eq!(
		warmup.blocked(Group::Gmail, "system", earlier),
		Some(earlier + INTERVAL)
	);
}
