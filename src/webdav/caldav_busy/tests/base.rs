use super::{BusyError, Limits, busy_periods_within};
use crate::webdav::rrule::parse_datetime;
use crate::webdav::test_support::{MKCOL_CALENDAR, send_as_alice, test_app};
use axum::http::StatusCode;

pub(super) fn dt(value: &str) -> i64 {
	parse_datetime(value).expect("datetime")
}

pub(super) fn small() -> Limits {
	Limits {
		window_secs: 40 * 86_400,
		items: 8,
		file_bytes: 4096,
		periods: 50,
		observe: None,
	}
}

/// An event of half an hour from `start` (`YYYYMMDDTHHMMSSZ`, minutes 00).
pub(super) fn event(uid: &str, start: &str, rule: Option<&str>) -> String {
	let rule = rule.map_or(String::new(), |rule| format!("RRULE:{rule}\r\n"));
	let end = format!("{}30{}", &start[..11], &start[13..]);
	format!("BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTART:{start}\r\nDTEND:{end}\r\n{rule}END:VEVENT\r\n")
}

pub(super) fn calendar_with(files: &[(&str, String)]) -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	for (name, events) in files {
		let text = format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{events}END:VCALENDAR\r\n");
		std::fs::write(dir.path().join(name), text).expect("write");
	}
	dir
}

pub(super) async fn scan(
	dir: &tempfile::TempDir,
	from: &str,
	to: &str,
) -> Result<Vec<(i64, i64)>, BusyError> {
	busy_periods_within(&[dir.path().to_path_buf()], dt(from), dt(to), small()).await
}

/// A scan whose item bound leaves room for the occurrences of a few series.
pub(super) async fn scan_roomy(
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

pub(super) fn vevent(start: &str, end: &str, extra: &str) -> String {
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
