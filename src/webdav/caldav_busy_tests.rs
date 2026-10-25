use super::{BusyError, Limits, Scan, busy_periods_within, collect_busy};
use crate::webdav::rrule::parse_datetime;
use crate::webdav::test_support::{MKCOL_CALENDAR, send_as_alice, test_app};
use axum::http::StatusCode;

fn dt(value: &str) -> i64 {
	parse_datetime(value).expect("datetime")
}

fn small() -> Limits {
	Limits {
		window_secs: 40 * 86_400,
		items: 8,
		file_bytes: 4096,
		periods: 50,
		observe: None,
	}
}

/// An event of half an hour from `start` (`YYYYMMDDTHHMMSSZ`, minutes 00).
fn event(uid: &str, start: &str, rule: Option<&str>) -> String {
	let rule = rule.map_or(String::new(), |rule| format!("RRULE:{rule}\r\n"));
	let end = format!("{}30{}", &start[..11], &start[13..]);
	format!("BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTART:{start}\r\nDTEND:{end}\r\n{rule}END:VEVENT\r\n")
}

fn calendar_with(files: &[(&str, String)]) -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	for (name, events) in files {
		let text = format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{events}END:VCALENDAR\r\n");
		std::fs::write(dir.path().join(name), text).expect("write");
	}
	dir
}

async fn scan(dir: &tempfile::TempDir, from: &str, to: &str) -> Result<Vec<(i64, i64)>, BusyError> {
	busy_periods_within(&[dir.path().to_path_buf()], dt(from), dt(to), small()).await
}

/// A scan whose item bound leaves room for the occurrences of a few series.
async fn scan_roomy(
	dir: &tempfile::TempDir,
	from: &str,
	to: &str,
) -> Result<Vec<(i64, i64)>, BusyError> {
	let limits = Limits {
		items: 10_000,
		..small()
	};
	busy_periods_within(&[dir.path().to_path_buf()], dt(from), dt(to), limits).await
}

#[tokio::test]
async fn a_range_wider_than_the_bound_is_refused() {
	let dir = calendar_with(&[("a.ics", event("a", "20260105T100000Z", None))]);
	assert!(
		scan(&dir, "20260101T000000Z", "20260210T000000Z")
			.await
			.is_ok()
	);
	assert_eq!(
		scan(&dir, "20260101T000000Z", "20260211T000000Z").await,
		Err(BusyError::TooMuchWork)
	);
}

#[tokio::test]
async fn too_many_files_or_events_are_refused() {
	let files: Vec<(String, String)> = (0..9)
		.map(|n| (format!("{n}.ics"), event("e", "20260105T100000Z", None)))
		.collect();
	let borrowed: Vec<(&str, String)> =
		files.iter().map(|(n, t)| (n.as_str(), t.clone())).collect();
	let many_files = calendar_with(&borrowed);
	assert_eq!(
		scan(&many_files, "20260101T000000Z", "20260110T000000Z").await,
		Err(BusyError::TooMuchWork)
	);
	let events: String = (0..9)
		.map(|n| event(&format!("e{n}"), "20260105T100000Z", None))
		.collect();
	let many_events = calendar_with(&[("one.ics", events)]);
	assert_eq!(
		scan(&many_events, "20260101T000000Z", "20260110T000000Z").await,
		Err(BusyError::TooMuchWork)
	);
}

#[tokio::test]
async fn a_calendar_file_over_the_size_bound_counts_as_busy_not_as_a_refusal() {
	let padding = format!("X-PAD:{}\r\n", "a".repeat(5000));
	let big = event("a", "20260105T100000Z", None) + &padding;
	let dir = calendar_with(&[("big.ics", big)]);
	let (from, to) = (dt("20260101T000000Z"), dt("20260110T000000Z"));
	assert_eq!(
		scan(&dir, "20260101T000000Z", "20260110T000000Z").await,
		Ok(vec![(from, to)])
	);
}

#[tokio::test]
async fn busy_periods_are_bounded_after_overlapping_ones_merge() {
	// Three daily series an hour apart: 90 distinct periods, over the bound.
	let apart: String = ["100000", "120000", "140000"]
		.iter()
		.map(|time| event(time, &format!("20260101T{time}Z"), Some("FREQ=DAILY")))
		.collect();
	let dir = calendar_with(&[("apart.ics", apart)]);
	assert_eq!(
		scan_roomy(&dir, "20260101T000000Z", "20260131T000000Z").await,
		Err(BusyError::TooMuchWork)
	);
	// The same three at one time overlap: 90 raw periods merge into 30.
	let same: String = (0..3)
		.map(|n| event(&format!("s{n}"), "20260101T100000Z", Some("FREQ=DAILY")))
		.collect();
	let dir = calendar_with(&[("same.ics", same)]);
	let got = scan_roomy(&dir, "20260101T000000Z", "20260131T000000Z")
		.await
		.expect("merged");
	assert_eq!(got.len(), 30);
}

#[tokio::test]
async fn a_free_busy_report_over_an_enormous_range_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _) = send_as_alice(&app, "MKCOL", "/cal/", &[], MKCOL_CALENDAR).await;
	assert_eq!(status, StatusCode::CREATED);
	let ics = format!(
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{}END:VCALENDAR\r\n",
		event("a", "19700101T000000Z", Some("FREQ=DAILY"))
	);
	let (status, _) = send_as_alice(&app, "PUT", "/cal/a.ics", &[], ics.as_bytes()).await;
	assert_eq!(status, StatusCode::CREATED);
	let report = |from: &str, to: &str| {
		format!(
			"<C:free-busy-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
			<C:time-range start=\"{from}\" end=\"{to}\"/></C:free-busy-query>"
		)
	};
	let (status, body) = send_as_alice(
		&app,
		"REPORT",
		"/cal/",
		&[("Depth", "1")],
		report("19700101T000000Z", "99990101T000000Z").as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(body.contains("number-of-matches-within-limits"), "{body}");
	let outbox = "BEGIN:VCALENDAR\r\nBEGIN:VFREEBUSY\r\nDTSTART:19700101T000000Z\r\n\
		DTEND:99990101T000000Z\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
	let (status, _) = send_as_alice(&app, "POST", "/outbox/", &[], outbox.as_bytes()).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, body) = send_as_alice(
		&app,
		"REPORT",
		"/cal/",
		&[("Depth", "1")],
		report("20260101T000000Z", "20260110T000000Z").as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(body.contains("FREEBUSY"), "{body}");
}

#[tokio::test]
async fn an_event_that_starts_before_the_range_and_runs_into_it_is_busy() {
	let two_hours = "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260105T090000Z\r\nDTEND:20260105T110000Z\r\nEND:VEVENT\r\n";
	let dir = calendar_with(&[("a.ics", two_hours.to_string())]);
	let got = scan(&dir, "20260105T100000Z", "20260105T120000Z").await;
	assert_eq!(
		got,
		Ok(vec![(dt("20260105T100000Z"), dt("20260105T110000Z"))])
	);
	let repeating = "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260101T230000Z\r\nDTEND:20260102T010000Z\r\nRRULE:FREQ=DAILY\r\nEND:VEVENT\r\n";
	let dir = calendar_with(&[("a.ics", repeating.to_string())]);
	let got = scan(&dir, "20260110T000000Z", "20260110T120000Z").await;
	assert_eq!(
		got,
		Ok(vec![(dt("20260110T000000Z"), dt("20260110T010000Z"))])
	);
}

fn vevent(start: &str, end: &str, extra: &str) -> String {
	format!("BEGIN:VEVENT\r\nUID:u\r\nDTSTART:{start}\r\nDTEND:{end}\r\n{extra}END:VEVENT\r\n")
}

#[tokio::test]
async fn a_rule_that_is_not_evaluated_is_refused_only_when_it_can_reach_the_range() {
	for rule in [
		"RRULE:FREQ=MONTHLY;BYDAY=MO;BYSETPOS=1\r\n",
		"RRULE:FREQ=HOURLY\r\n",
		"RRULE:FREQ=YEARLY;BYDAY=MO\r\n",
		"RRULE:FREQ=WEEKLY;BYWEEKNO=3\r\n",
	] {
		let text = vevent("20260105T090000Z", "20260105T100000Z", rule);
		let dir = calendar_with(&[("a.ics", text)]);
		assert_eq!(
			scan(&dir, "20260101T000000Z", "20260110T000000Z").await,
			Err(BusyError::Unsupported),
			"{rule}"
		);
		// Starting after the range, it cannot reach it.
		assert_eq!(
			scan(&dir, "20251201T000000Z", "20251210T000000Z").await,
			Ok(vec![])
		);
	}
	// A series that ended before the range cannot reach it either.
	let ended = vevent(
		"20100105T090000Z",
		"20100105T100000Z",
		"RRULE:FREQ=MONTHLY;BYSETPOS=1;BYDAY=MO;UNTIL=20100301T000000Z\r\n",
	);
	let dir = calendar_with(&[("a.ics", ended)]);
	assert_eq!(
		scan(&dir, "20260101T000000Z", "20260110T000000Z").await,
		Ok(vec![])
	);
}

#[tokio::test]
async fn a_realistic_calendar_is_answered_exactly() {
	let calendar = [
		// Weekly on Monday and Wednesday, from Monday 5 January 2026.
		vevent(
			"20260105T090000Z",
			"20260105T093000Z",
			"RRULE:FREQ=WEEKLY;BYDAY=MO,WE\r\n",
		),
		// A series that ended in 2010.
		vevent(
			"20100105T090000Z",
			"20100105T100000Z",
			"RRULE:FREQ=WEEKLY;BYDAY=MO;UNTIL=20100301T000000Z\r\n",
		),
		// Second Tuesday of every month.
		vevent(
			"20260113T140000Z",
			"20260113T150000Z",
			"RRULE:FREQ=MONTHLY;BYDAY=2TU\r\n",
		),
		// A single date added to a series.
		vevent(
			"20260102T080000Z",
			"20260102T083000Z",
			"RDATE:20260116T080000Z\r\n",
		),
	]
	.concat();
	let dir = calendar_with(&[("a.ics", calendar)]);
	let got = scan_roomy(&dir, "20260112T000000Z", "20260120T000000Z")
		.await
		.expect("answered");
	let busy = |from: &str, to: &str| (dt(from), dt(to));
	assert_eq!(
		got,
		vec![
			busy("20260112T090000Z", "20260112T093000Z"),
			busy("20260114T090000Z", "20260114T093000Z"),
			busy("20260113T140000Z", "20260113T150000Z"),
			busy("20260116T080000Z", "20260116T083000Z"),
			busy("20260119T090000Z", "20260119T093000Z"),
		]
		.into_iter()
		.collect::<std::collections::BTreeSet<_>>()
		.into_iter()
		.collect::<Vec<_>>()
	);
}

#[tokio::test]
async fn a_calendar_that_cannot_be_read_is_an_error_not_free_time() {
	let dir = calendar_with(&[("a.ics", event("a", "20260105T100000Z", None))]);
	let not_a_directory = dir.path().join("a.ics");
	let got = busy_periods_within(
		&[not_a_directory],
		dt("20260101T000000Z"),
		dt("20260110T000000Z"),
		small(),
	)
	.await;
	assert_eq!(got, Err(BusyError::Unreadable));
}

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
