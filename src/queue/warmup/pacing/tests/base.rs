use super::*;

/// Midnight UTC of an arbitrary day, in milliseconds.
const MIDNIGHT: u64 = 20_000 * DAY_MS;

#[test]
fn a_cap_of_fifty_comes_one_every_twenty_nine_minutes_after_a_burst_of_three() {
	assert_eq!((interval_ms(50), burst(50)), (1_728_000, 3));
	assert_eq!((interval_ms(1), burst(1)), (DAY_MS, 1));
	assert_eq!((interval_ms(5000), burst(5000)), (17_280, 209));
}

#[test]
fn an_idle_group_sends_only_its_burst_at_midnight() {
	// The last unit went out a day ago: the group is idle.
	let (taken, tat) = take(50, MIDNIGHT - DAY_MS, MIDNIGHT, 1000);
	assert_eq!(taken, 3);
	assert_eq!(tat, MIDNIGHT + 3 * 1_728_000);
	assert_eq!(next_ms(50, tat, MIDNIGHT), MIDNIGHT + 1_728_000);
	// Nothing more until then.
	assert_eq!(take(50, tat, MIDNIGHT + 1_727_999, 1000), (0, tat));
	assert_eq!(take(50, tat, MIDNIGHT + 1_728_000, 1000).0, 1);
}

#[test]
fn units_are_spread_over_the_day_not_sent_in_one_go() {
	// Ask for a thousand every minute of the day, as a full queue would.
	let mut tat = 0;
	let mut sent_at = Vec::new();
	for minute in 0..(24 * 60) {
		let now = MIDNIGHT + minute * 60_000;
		let (taken, next) = take(50, tat, now, 1000);
		tat = next;
		sent_at.extend(std::iter::repeat_n(minute, taken as usize));
	}
	let first_hour = sent_at.iter().filter(|minute| **minute < 60).count();
	let last_hour = sent_at.iter().filter(|minute| **minute >= 23 * 60).count();
	// Pacing alone lets the burst exceed the day by two; the daily count
	// is what holds the day to the cap.
	assert_eq!((sent_at.len(), first_hour, last_hour), (52, 5, 2));
}

#[test]
fn units_given_back_can_be_taken_again() {
	let (taken, tat) = take(50, 0, MIDNIGHT, 3);
	assert_eq!(taken, 3);
	let tat = give_back(50, tat, 3);
	assert_eq!(tat, MIDNIGHT);
	assert_eq!(take(50, tat, MIDNIGHT, 3).0, 3);
}

#[test]
fn far_future_times_saturate_instead_of_wrapping() {
	let (taken, tat) = take(1, u64::MAX - 5, u64::MAX - 5, 3);
	assert_eq!((taken, tat), (1, u64::MAX));
}

#[test]
fn an_arrival_time_left_far_ahead_by_the_clock_waits_one_unit() {
	// The clock went back after a unit was taken at a later time.
	assert_eq!(next_ms(1, u64::MAX, 0), DAY_MS);
	assert_eq!(
		next_ms(50, MIDNIGHT + DAY_MS, MIDNIGHT),
		MIDNIGHT + 1_728_000
	);
}
