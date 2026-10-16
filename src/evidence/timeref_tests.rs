use std::time::{Duration, Instant};

use super::*;

/// What a reading says, without the wall clock it was made from.
fn said(reading: Reading) -> (u64, bool) {
	(reading.time, reading.sound)
}

const NOW: u64 = 1_792_000_000;
const DAY: u64 = 86_400;

#[test]
fn a_clock_with_nothing_to_compare_to_is_believed() {
	let time = TimeRef::new(0);
	let reading = time.read_at(NOW, Instant::now());
	assert_eq!(said(reading), (NOW, true));
}

#[test]
fn a_clock_that_jumps_ahead_between_two_readings_is_not_followed() {
	let time = TimeRef::new(0);
	let start = Instant::now();
	assert!(time.read_at(NOW, start).sound);
	let later = start + Duration::from_secs(10);
	let reading = time.read_at(NOW + 400 * DAY, later);
	assert!(!reading.sound);
	assert_eq!(
		reading.time,
		NOW + 10,
		"the estimate follows the monotonic clock"
	);
	// The clock is put right: it is believed again, with no restart.
	let right = time.read_at(NOW + 70, start + Duration::from_secs(70));
	assert_eq!(said(right), (NOW + 70, true));
}

#[test]
fn a_clock_that_steps_far_back_is_not_followed() {
	let time = TimeRef::new(0);
	let start = Instant::now();
	assert!(time.read_at(NOW, start).sound);
	let later = start + Duration::from_secs(30);
	// A minute or two back is a step of the clock.
	assert!(time.read_at(NOW + 30 - 120, later).sound);
	let reading = time.read_at(NOW - 2 * 3600, later);
	assert!(!reading.sound);
	assert!(reading.time >= NOW, "{}", reading.time);
}

#[test]
fn time_that_really_passed_is_no_jump() {
	let time = TimeRef::new(0);
	let start = Instant::now();
	assert!(time.read_at(NOW, start).sound);
	let week = Duration::from_secs(7 * DAY);
	assert!(time.read_at(NOW + 7 * DAY, start + week).sound);
}

#[test]
fn a_start_is_judged_by_the_newest_record_the_disk_holds() {
	let newest = NOW - 3 * DAY;
	let start = Instant::now();
	// A few days after the newest record: believed.
	assert!(TimeRef::new(newest).read_at(NOW, start).sound);
	// A year after: not believed, and nothing is later than the record.
	let ahead = TimeRef::new(newest).read_at(newest + 400 * DAY, start);
	assert_eq!(said(ahead), (newest, false));
	// Before it: the record happened, the clock is wrong.
	let behind = TimeRef::new(newest).read_at(newest - 2 * 3600, start);
	assert_eq!(said(behind), (newest, false));
	// A step of a few minutes back is not.
	assert!(TimeRef::new(newest).read_at(newest - 600, start).sound);
}

#[test]
fn the_estimate_after_a_refused_start_keeps_counting() {
	let newest = NOW - DAY;
	let time = TimeRef::new(newest);
	let start = Instant::now();
	assert_eq!(time.read_at(newest + 400 * DAY, start).time, newest);
	let later = time.read_at(newest + 400 * DAY, start + Duration::from_secs(90));
	assert_eq!(said(later), (newest + 90, false));
}

#[test]
fn a_clock_that_is_corrected_after_the_start_is_believed_once_it_is_right() {
	let newest = NOW - DAY;
	let time = TimeRef::new(newest);
	let start = Instant::now();
	// Started with the clock in 1970, as a machine with a dead RTC does.
	assert!(!time.read_at(86_400, start).sound);
	assert!(time.read_at(NOW, start + Duration::from_secs(30)).sound);
}

#[test]
fn a_clock_cannot_be_walked_ahead_in_steps_each_within_the_slack() {
	let time = TimeRef::new(0);
	let start = Instant::now();
	assert!(time.read_at(NOW, start).sound);
	// Each second the clock gains 250 s more than it should: believed while
	// the reference has not moved, then not.
	let mut believed = 0;
	for second in 1..=20_u64 {
		let wall = NOW + second + 250 * second;
		if time
			.read_at(wall, start + Duration::from_secs(second))
			.sound
		{
			believed += 1;
		}
	}
	assert_eq!(believed, 1, "only the first step is within the slack");
}

#[test]
fn a_timestamp_authority_decides_what_time_it_is() {
	let newest = NOW - 40 * DAY;
	let time = TimeRef::new(newest);
	let start = Instant::now();
	// Forty days after the newest record is not believed on its own.
	assert!(!time.read_at(NOW, start).sound);
	// A token says that is the time.
	time.witness(NOW, start);
	assert!(time.read_at(NOW + 5, start + Duration::from_secs(5)).sound);
}

#[test]
fn what_waits_is_aged_by_the_earlier_of_the_clock_and_the_estimate() {
	let time = TimeRef::new(0);
	let start = Instant::now();
	assert_eq!(time.read_at(NOW, start).cautious(), NOW);
	// A clock a year ahead does not make mail a year old.
	let ahead = time.read_at(NOW + 400 * DAY, start + Duration::from_secs(10));
	assert_eq!(ahead.cautious(), NOW + 10);
	// And one that fell behind does not either.
	let behind = time.read_at(NOW - 7200, start + Duration::from_secs(20));
	assert_eq!(behind.cautious(), NOW - 7200);
}
