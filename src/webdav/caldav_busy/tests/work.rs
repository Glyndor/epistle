//! What a scan costs: merging, cancellation, enormous durations and the per-request work budget.

use super::base::*;
use super::{BusyError, Limits, Scan, busy_periods_within, collect_busy};

#[test]
fn merging_is_paid_for_by_the_periods_added_since_the_last_merge() {
	let limits = Limits {
		window_secs: 40 * 86_400,
		items: 100_000,
		file_bytes: 1 << 30,
		periods: 700,
		observe: None,
	};
	// 23 disjoint daily series: 690 periods that survive every merge.
	let mut ics = String::new();
	for n in 0..23 {
		let time = format!("{n:02}0000");
		ics += &event(
			&format!("base{n}"),
			&format!("20260101T{time}Z"),
			Some("FREQ=DAILY"),
		);
	}
	// 2000 events that sit inside the first ones, 30 more periods each.
	for n in 0..2000 {
		ics += &event(&format!("dup{n}"), "20260101T000000Z", Some("FREQ=DAILY"));
	}
	let mut scan = Scan::default();
	collect_busy(
		&ics,
		dt("20260101T000000Z"),
		dt("20260131T000000Z"),
		&mut scan,
		limits,
	)
	.expect("within the bounds");
	let pushed = 30 * 2023u64;
	assert!(
		scan.merged <= 4 * pushed,
		"merges handled {} periods for {pushed} pushed",
		scan.merged
	);
}

#[test]
fn a_scan_stops_when_the_request_is_gone() {
	use std::sync::atomic::Ordering;
	let mut scan = Scan::default();
	scan.cancel.store(true, Ordering::Relaxed);
	let ics = event("a", "20260105T100000Z", None);
	let got = collect_busy(
		&ics,
		dt("20260101T000000Z"),
		dt("20260110T000000Z"),
		&mut scan,
		small(),
	);
	assert_eq!(got, Err(BusyError::Unreadable));
}

#[tokio::test]
async fn dropping_the_scan_sets_the_flag_the_blocking_work_watches() {
	use std::sync::atomic::Ordering;
	let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	drop(super::CancelOnDrop(std::sync::Arc::clone(&flag)));
	assert!(flag.load(Ordering::Relaxed));
}

#[tokio::test]
async fn an_enormous_duration_cannot_multiply_the_work() {
	// A daily series from 1900 whose events last a thousand years overlaps
	// the range from hundreds of thousands of occurrences.
	let text = vevent(
		"19000101T000000Z",
		"29990101T000000Z",
		"RRULE:FREQ=DAILY\r\n",
	);
	let dir = calendar_with(&[("a.ics", text)]);
	let limits = Limits {
		items: 2000,
		..small()
	};
	let got = busy_periods_within(
		&[dir.path().to_path_buf()],
		dt("20260101T000000Z"),
		dt("20260110T000000Z"),
		limits,
	)
	.await;
	assert_eq!(got, Err(BusyError::TooMuchWork));
}

static SCANNED_ON: std::sync::Mutex<Option<std::thread::ThreadId>> = std::sync::Mutex::new(None);

fn note_thread() {
	*SCANNED_ON.lock().expect("lock") = Some(std::thread::current().id());
}

#[tokio::test]
async fn the_scan_runs_off_the_async_worker() {
	let dir = calendar_with(&[("a.ics", event("a", "20260105T100000Z", None))]);
	let limits = Limits {
		observe: Some(note_thread),
		..small()
	};
	busy_periods_within(
		&[dir.path().to_path_buf()],
		dt("20260101T000000Z"),
		dt("20260110T000000Z"),
		limits,
	)
	.await
	.expect("answered");
	let scanned_on = SCANNED_ON.lock().expect("lock").expect("the scan ran");
	assert_ne!(scanned_on, std::thread::current().id());
}

#[test]
fn the_occurrences_of_every_event_count_against_the_request() {
	// Each series gives 30 occurrences, under the bound of 50 on its own; the
	// second one runs the request past it.
	let limits = Limits {
		items: 50,
		..small()
	};
	let series = |uid: &str| event(uid, "20260101T100000Z", Some("FREQ=DAILY"));
	let ics = [series("a"), series("b"), series("c")].concat();
	let mut scan = Scan::default();
	let got = collect_busy(
		&ics,
		dt("20260101T000000Z"),
		dt("20260131T000000Z"),
		&mut scan,
		limits,
	);
	assert_eq!(got, Err(BusyError::TooMuchWork));
}

#[tokio::test]
async fn a_duration_or_an_all_day_start_gives_the_event_its_length() {
	let busy = |from: &str, to: &str| vec![(dt(from), dt(to))];
	let with_duration =
		"BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260105T080000Z\r\nDURATION:PT1H30M\r\nEND:VEVENT\r\n";
	let dir = calendar_with(&[("a.ics", with_duration.to_string())]);
	assert_eq!(
		scan(&dir, "20260105T000000Z", "20260106T000000Z").await,
		Ok(busy("20260105T080000Z", "20260105T093000Z"))
	);
	let all_day = "BEGIN:VEVENT\r\nUID:a\r\nDTSTART;VALUE=DATE:20260106\r\nEND:VEVENT\r\n";
	let dir = calendar_with(&[("a.ics", all_day.to_string())]);
	assert_eq!(
		scan(&dir, "20260105T000000Z", "20260108T000000Z").await,
		Ok(busy("20260106T000000Z", "20260107T000000Z"))
	);
	// DTEND wins over DURATION, and a timed start with neither is a point.
	let both = "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260105T080000Z\r\nDTEND:20260105T090000Z\r\nDURATION:PT5H\r\nEND:VEVENT\r\n";
	let dir = calendar_with(&[("a.ics", both.to_string())]);
	assert_eq!(
		scan(&dir, "20260105T000000Z", "20260106T000000Z").await,
		Ok(busy("20260105T080000Z", "20260105T090000Z"))
	);
	let point =
		"BEGIN:VEVENT\r\nUID:a\r\nDTSTART;VALUE=DATE-TIME:20260105T080000Z\r\nEND:VEVENT\r\n";
	let dir = calendar_with(&[("a.ics", point.to_string())]);
	assert_eq!(
		scan(&dir, "20260105T000000Z", "20260106T000000Z").await,
		Ok(vec![])
	);
}
