//! One sender's share of a group's day: the whole cap while nobody else
//! waits for it, three quarters while somebody does.

use super::tests::{enable, granted};
use super::*;
use crate::queue::warmup::settings::Action;

/// Midnight UTC of the test day.
const MIDNIGHT: u64 = 20_375 * 86_400;

/// A warm-up with the gmail cap at 24 a day: one unit an hour, no burst.
fn hourly(dir: &Path) -> Warmup {
	enable(dir, |settings| {
		settings.order(Group::Gmail, Action::Set { cap: 24 });
	});
	Warmup::open(dir, None, MIDNIGHT)
}

#[test]
fn a_single_sender_may_use_the_whole_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = hourly(dir.path());
	let mut sent = 0;
	// The queue asks every five minutes, all day.
	for step in 0..(24 * 12) {
		let now = MIDNIGHT + step * 300;
		sent += granted(warmup.grant(Group::Gmail, "account:sena", 10, now)).0;
	}
	assert_eq!(
		sent, 24,
		"nobody else waits, so the whole cap is the sender's"
	);
}

#[test]
fn one_sender_takes_at_most_three_quarters_while_another_waits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = hourly(dir.path());
	let (mut bulk, mut small) = (0, 0);
	for step in 0..(24 * 12) {
		let now = MIDNIGHT + step * 300;
		// The flood asks first every time, and still leaves a quarter.
		bulk += granted(warmup.grant(Group::Gmail, "account:bulk", 10, now)).0;
		small += granted(warmup.grant(Group::Gmail, "system", 1, now)).0;
	}
	assert_eq!((bulk, small), (18, 6));
	assert_eq!(
		warmup.blocked(Group::Gmail, "account:bulk", MIDNIGHT + 86_399),
		Some(MIDNIGHT + 86_400),
		"the flood waits for tomorrow"
	);
}

#[test]
fn a_sender_that_stopped_waiting_no_longer_holds_the_other_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = hourly(dir.path());
	// The system waits once, at midnight, and then has nothing left.
	granted(warmup.grant(Group::Gmail, "account:bulk", 1, MIDNIGHT));
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 1, MIDNIGHT)),
		(0, MIDNIGHT + 3600)
	);
	let mut bulk = 1;
	for step in 1..(24 * 12) {
		let now = MIDNIGHT + step * 300;
		bulk += granted(warmup.grant(Group::Gmail, "account:bulk", 10, now)).0;
	}
	assert_eq!(bulk, 24);
}
