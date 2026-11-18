use super::*;
use crate::evidence::timeref::TimeRef;

fn reading(sound: bool, wall: u64, estimate: u64) -> Reading {
	Reading {
		time: estimate,
		sound,
		wall,
		estimate,
	}
}

#[test]
fn a_believed_clock_is_the_time_to_act_on() {
	let mut warned = false;
	assert_eq!(
		believed(reading(true, 1000, 900), &mut warned, "t"),
		Some(1000)
	);
	assert!(!warned);
}

#[test]
fn a_clock_that_is_not_believed_removes_nothing_and_says_so_once() {
	let mut warned = false;
	assert_eq!(believed(reading(false, 5000, 900), &mut warned, "t"), None);
	assert!(warned);
	assert_eq!(believed(reading(false, 5000, 900), &mut warned, "t"), None);
	assert!(warned);
	assert_eq!(
		believed(reading(true, 1000, 900), &mut warned, "t"),
		Some(1000)
	);
	assert!(!warned, "the return of the clock resets the warning");
}

#[test]
fn a_wall_clock_far_behind_the_newest_record_is_not_believed() {
	// The disk holds a record from a day nobody has reached: a clock reset to
	// the past, as a dead battery does.
	let floor = 2_000_000_000;
	let time = TimeRef::new(floor);
	let reading = time.read_at(1_700_000_000, std::time::Instant::now());
	let mut warned = false;
	assert_eq!(believed(reading, &mut warned, "t"), None);
}
