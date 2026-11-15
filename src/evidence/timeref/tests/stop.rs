//! A gap explained by a recorded clean shutdown, and the lines the check writes.

use std::time::{Duration, Instant};

use super::*;
use crate::cli::trace::capture::{CapturedEvent, run_with_capture};

const NOW: u64 = 1_792_000_000;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;

fn message(event: &CapturedEvent) -> &str {
	&event.fields["message"]
}

fn errors(events: &[CapturedEvent]) -> Vec<&CapturedEvent> {
	events
		.iter()
		.filter(|event| event.level == tracing::Level::ERROR)
		.collect()
}

#[test]
fn a_start_after_a_recorded_clean_stop_is_believed_and_says_how_long_it_was_stopped() {
	let newest = NOW - 7 * HOUR;
	let stop = newest + 120;
	let time = TimeRef::new(newest).after_stop(Some(stop));
	let mut said = None;
	let events = run_with_capture(|| said = Some(time.read_at(NOW, Instant::now())));
	let reading = said.expect("read");
	assert!(reading.sound, "{reading:?}");
	assert_eq!(reading.time, NOW);
	assert!(errors(&events).is_empty(), "{events:?}");
	assert_eq!(events.len(), 1, "{events:?}");
	assert_eq!(events[0].level, tracing::Level::INFO);
	assert_eq!(events[0].fields["downtime_secs"], (NOW - stop).to_string());
	assert!(
		message(&events[0]).contains("stopped for 6h 58m"),
		"{}",
		message(&events[0])
	);
}

#[test]
fn the_explanation_is_given_once() {
	let newest = NOW - 7 * HOUR;
	let time = TimeRef::new(newest).after_stop(Some(newest + 120));
	let start = Instant::now();
	let events = run_with_capture(|| {
		for second in 0..3 {
			assert!(
				time.read_at(NOW + second, start + Duration::from_secs(second))
					.sound
			);
		}
	});
	assert_eq!(events.len(), 1, "{events:?}");
}

#[test]
fn a_start_with_no_recorded_stop_keeps_the_error_and_names_the_gap() {
	let newest = NOW - 7 * HOUR;
	let time = TimeRef::new(newest);
	let mut said = None;
	let events = run_with_capture(|| said = Some(time.read_at(NOW, Instant::now())));
	let reading = said.expect("read");
	assert!(!reading.sound);
	let errors = errors(&events);
	assert_eq!(errors.len(), 1, "{events:?}");
	assert_eq!(errors[0].fields["differ_secs"], (7 * HOUR).to_string());
	assert_eq!(errors[0].fields["wall"], NOW.to_string());
	assert_eq!(errors[0].fields["estimate"], newest.to_string());
	let text = message(errors[0]);
	assert!(text.contains("differ by 7h 0m"), "{text}");
	assert!(
		text.contains("monotonic clock"),
		"the sources are named: {text}"
	);
	assert!(
		text.contains("nothing is deleted, sealed or expired"),
		"{text}"
	);
	assert!(text.contains("epistle evidence clock accept"), "{text}");
}

#[test]
fn a_clock_far_past_the_recorded_stop_is_a_jump_and_not_a_stop() {
	let newest = NOW - 3 * HOUR;
	let time = TimeRef::new(newest).after_stop(Some(newest + 60));
	let wall = newest + 60 + MAX_KNOWN_STOP_SECS + 1;
	let mut said = None;
	let events = run_with_capture(|| said = Some(time.read_at(wall, Instant::now())));
	assert!(!said.expect("read").sound);
	assert_eq!(errors(&events).len(), 1, "{events:?}");
	let edge = TimeRef::new(newest).after_stop(Some(newest + 60));
	assert!(
		edge.read_at(newest + 60 + MAX_KNOWN_STOP_SECS, Instant::now())
			.sound
	);
}

#[test]
fn a_clock_behind_the_recorded_stop_is_not_believed() {
	// The clock went back two days since the server stopped: not a stop.
	let newest = NOW - 3 * HOUR;
	let stop = newest + 60;
	let time = TimeRef::new(newest).after_stop(Some(stop));
	let wall = stop - 2 * DAY;
	let mut said = None;
	let events = run_with_capture(|| said = Some(time.read_at(wall, Instant::now())));
	assert!(!said.expect("read").sound);
	assert_eq!(errors(&events).len(), 1, "{events:?}");
	assert!(
		events
			.iter()
			.all(|event| event.level != tracing::Level::INFO),
		"{events:?}"
	);
}

#[test]
fn a_recorded_stop_older_than_the_newest_record_explains_nothing() {
	// The server ran after that stop (it wrote records) and then died.
	let newest = NOW - 7 * HOUR;
	let stale = newest - DAY;
	let time = TimeRef::new(newest).after_stop(Some(stale));
	assert!(!time.read_at(NOW, Instant::now()).sound);
}

#[test]
fn a_log_that_could_not_be_read_is_not_explained_by_a_stop() {
	let time = TimeRef::unknown().after_stop(Some(NOW - HOUR));
	let mut said = None;
	let events = run_with_capture(|| said = Some(time.read_at(NOW, Instant::now())));
	assert!(!said.expect("read").sound);
	let errors = errors(&events);
	assert_eq!(errors.len(), 1);
	assert!(
		message(errors[0]).contains("could not be read"),
		"{}",
		message(errors[0])
	);
}

#[test]
fn when_the_check_passes_again_one_line_says_so() {
	let newest = NOW - 7 * HOUR;
	let time = TimeRef::new(newest);
	let start = Instant::now();
	let events = run_with_capture(|| {
		assert!(!time.read_at(NOW, start).sound);
		// Still refused: the error is not repeated.
		assert!(
			!time
				.read_at(NOW + 10, start + Duration::from_secs(10))
				.sound
		);
		time.witness(NOW + 20, start + Duration::from_secs(20));
		assert!(
			time.read_at(NOW + 30, start + Duration::from_secs(30))
				.sound
		);
		assert!(
			time.read_at(NOW + 40, start + Duration::from_secs(40))
				.sound
		);
	});
	assert_eq!(errors(&events).len(), 1, "{events:?}");
	let infos: Vec<_> = events
		.iter()
		.filter(|event| event.level == tracing::Level::INFO)
		.collect();
	assert_eq!(infos.len(), 1, "{events:?}");
	assert_eq!(infos[0].fields["refused_secs"], "30");
	assert!(
		message(infos[0]).contains("resume"),
		"{}",
		message(infos[0])
	);
}

#[test]
fn a_clock_that_is_fine_from_the_start_writes_nothing() {
	let time = TimeRef::new(NOW - 60);
	let events = run_with_capture(|| {
		assert!(time.read_at(NOW, Instant::now()).sound);
	});
	assert!(events.is_empty(), "{events:?}");
}
