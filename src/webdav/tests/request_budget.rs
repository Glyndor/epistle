//! The work one `calendar-query` object may cost, and what the report says
//! of an object that costs more.
//!
//! Every component of an object and every recurrence expansion it runs share
//! one budget, so a file with many series cannot multiply the bound. An object
//! that exhausts it is refused with its own `507`, and the request carries on
//! with the other objects.

use super::hostile_content::calendar;
use crate::webdav::caldav_filter::{self, TooMuchWork};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The variable that tells a child process it is the one that does the work.
const CHILD: &str = "EPISTLE_QUERY_BUDGET_CASE";

/// How long the search of one object may take before the harness kills it.
const DEADLINE: Duration = Duration::from_secs(20);

/// One component with its own start, rule and summary.
fn event(start: &str, rule: &str, summary: &str) -> String {
	format!(
		"BEGIN:VEVENT\r\nDTSTART:{start}\r\nRRULE:{rule}\r\nSUMMARY:{summary}\r\nEND:VEVENT\r\n"
	)
}

/// A `calendar-query` body that asks for the window and nothing else.
fn query(from: &str, to: &str) -> String {
	format!(
		"<C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:D=\"DAV:\"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"><C:time-range start=\"{from}\" end=\"{to}\"/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>"
	)
}

/// A `calendar-query` body that asks for the window and a summary.
fn query_summary(from: &str, to: &str, text: &str) -> String {
	format!(
		"<C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:D=\"DAV:\"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"><C:time-range start=\"{from}\" end=\"{to}\"/><C:prop-filter name=\"SUMMARY\"><C:text-match>{text}</C:text-match></C:prop-filter></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>"
	)
}

/// The filter of [`query`].
fn filter(from: &str, to: &str) -> caldav_filter::CalendarQueryFilter {
	caldav_filter::parse(&query(from, to)).expect("supported filter")
}

/// Run the work in a child process under a deadline: a search that runs away
/// is killed instead of hanging the suite.
fn isolated(name: &str, work: impl FnOnce()) {
	if std::env::var_os(CHILD).is_some() {
		work();
		return;
	}
	let log = tempfile::tempfile().expect("worker log");
	let mut child = Command::new(std::env::current_exe().expect("test executable"))
		.args([
			"--exact",
			&format!("webdav::tests::request_budget::{name}"),
			"--nocapture",
		])
		.env(CHILD, name)
		.stdout(Stdio::from(log.try_clone().expect("log clone")))
		.stderr(Stdio::from(log.try_clone().expect("log clone")))
		.spawn()
		.expect("worker");
	let started = Instant::now();
	let status = loop {
		if let Some(status) = child.try_wait().expect("worker status") {
			break Some(status);
		}
		if started.elapsed() > DEADLINE {
			child.kill().expect("kill stalled search");
			child.wait().expect("reap stalled search");
			break None;
		}
		std::thread::sleep(Duration::from_millis(20));
	};
	use std::io::{Read, Seek};
	let mut log = log;
	log.rewind().expect("rewind log");
	let mut output = String::new();
	log.read_to_string(&mut output).expect("read worker log");
	assert!(
		status.is_some_and(|s| s.success()),
		"{name}: {status:?}\n{output}"
	);
}

/// The saved defect: one object under 4 MiB with twenty thousand daily series
/// and a window that reaches the year 9999. Every series used to get a budget
/// of its own, so the search asked for billions of steps and did not finish.
#[test]
fn many_series_in_one_object_stay_inside_the_work_bound() {
	isolated(
		"many_series_in_one_object_stay_inside_the_work_bound",
		|| {
			let ics = calendar(&event("20260101T000000Z", "FREQ=DAILY", "decoy").repeat(20_000));
			assert!(ics.len() < 4 * 1024 * 1024);
			let f = caldav_filter::parse(&query_summary(
				"20260101T000000Z",
				"99990101T000000Z",
				"absent",
			))
			.expect("supported filter");
			// No series of the object carries the summary the query asks for,
			// so the object is not one of the results.
			assert_eq!(caldav_filter::matches(&f, &ics), Ok(false));
		},
	);
}

/// The work of one object is shared by its components: two series that fit
/// inside the bound each do not fit inside it together.
#[test]
fn the_work_of_one_object_is_shared_by_its_components() {
	// A counted series walks its periods from the start, sixty thousand of
	// them, and ends before the window: one component fits inside the bound.
	let series = event(
		"20260101T000000Z",
		"FREQ=DAILY;COUNT=60000;BYDAY=MO,TU,WE,TH,FR,SA,SU",
		"decoy",
	);
	let f = filter("90000101T000000Z", "90010101T000000Z");
	assert_eq!(caldav_filter::matches(&f, &calendar(&series)), Ok(false));
	// Two of them cost more than the bound together, so the object cannot be
	// searched: it is refused, not called a non-match.
	assert_eq!(
		caldav_filter::matches(&f, &calendar(&series.repeat(2))),
		Err(TooMuchWork)
	);
}

/// A series the search cannot reach leaves the object undecided, and the
/// caller is told so instead of reading a non-match.
#[test]
fn an_object_whose_series_cannot_be_reached_is_refused() {
	// The counted selector walks from the start and exhausts the budget long
	// before the window of the year 2500, so the answer is not known.
	let ics = calendar(&event(
		"20260101T000000Z",
		"FREQ=DAILY;COUNT=1000000;BYDAY=MO,TU,WE,TH,FR,SA,SU",
		"decoy",
	));
	let f = filter("25000101T000000Z", "25000102T000000Z");
	assert_eq!(caldav_filter::matches(&f, &ics), Err(TooMuchWork));
}

/// The budget is one for the object, so the second comp-filter does not get a
/// budget of its own either.
#[test]
fn the_work_of_one_object_is_shared_by_its_comp_filters() {
	let ics = calendar(&format!(
		"{}BEGIN:VTODO\r\nDTSTART:20260101T000000Z\r\nRRULE:FREQ=DAILY\r\nSUMMARY:todo\r\nEND:VTODO\r\n",
		event("20260101T000000Z", "FREQ=DAILY", "event")
	));
	let f = caldav_filter::parse(
		"<C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:D=\"DAV:\"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"><C:time-range start=\"20260101T000000Z\" end=\"99990101T000000Z\"/></C:comp-filter><C:comp-filter name=\"VTODO\"><C:time-range start=\"20260101T000000Z\" end=\"99990101T000000Z\"/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>",
	)
	.expect("supported filter");
	// The series of the event spends the budget of the object walking the
	// window, so the series of the task cannot be looked at and the object
	// is refused instead of answered with a guess.
	assert_eq!(caldav_filter::matches(&f, &ics), Err(TooMuchWork));
}

/// A small object is answered exactly, whichever way the window falls.
#[test]
fn a_small_object_is_answered_exactly() {
	let ics = calendar(&event("20260101T000000Z", "FREQ=DAILY;COUNT=3", "needle"));
	// The window holds the second occurrence.
	assert_eq!(
		caldav_filter::matches(&filter("20260102T000000Z", "20260103T000000Z"), &ics),
		Ok(true)
	);
	// A window past the last occurrence holds none.
	assert_eq!(
		caldav_filter::matches(&filter("20260104T000000Z", "20260105T000000Z"), &ics),
		Ok(false)
	);
	// A summary the object does not carry rules it out.
	let f = caldav_filter::parse(&query_summary(
		"20260101T000000Z",
		"20260105T000000Z",
		"absent",
	))
	.expect("supported filter");
	assert_eq!(caldav_filter::matches(&f, &ics), Ok(false));
}

/// A report carries the objects it could search and refuses the one it could
/// not, so the request is not lost.
#[tokio::test]
async fn a_report_refuses_the_exhausted_object_and_keeps_the_others() {
	use crate::webdav::test_support::{MKCOL_CALENDAR, send_as_alice, test_app};
	use axum::http::StatusCode;
	let dir = tempfile::tempdir().unwrap();
	let app = test_app(dir.path());
	assert_eq!(
		send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR)
			.await
			.0,
		StatusCode::CREATED
	);
	let series = event(
		"20260101T000000Z",
		"FREQ=DAILY;COUNT=60000;BYDAY=MO,TU,WE,TH,FR,SA,SU",
		"decoy",
	);
	for (name, events) in [
		("exhausted", series.repeat(2)),
		(
			"small",
			event("90000101T000000Z", "FREQ=DAILY;COUNT=3", "needle"),
		),
	] {
		assert_eq!(
			send_as_alice(
				&app,
				"PUT",
				&format!("/cal/{name}.ics"),
				&[],
				calendar(&events).as_bytes()
			)
			.await
			.0,
			StatusCode::CREATED
		);
	}
	let (status, body) = send_as_alice(
		&app,
		"REPORT",
		"/cal",
		&[("Depth", "1")],
		query("90000101T000000Z", "90010101T000000Z").as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let refused = body
		.split("<D:response>")
		.find(|part| part.contains("/cal/exhausted.ics"))
		.expect("the refused object is named");
	assert!(refused.contains("507 Insufficient Storage"), "{body}");
	let kept = body
		.split("<D:response>")
		.find(|part| part.contains("/cal/small.ics"))
		.expect("the other objects are still searched");
	assert!(kept.contains("200 OK"), "{body}");
}
