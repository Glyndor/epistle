//! The work one `calendar-query` request may cost in all, over every object
//! of the collection it searches.
//!
//! The bound on one object (see `request_budget`) does not bound a request:
//! a collection of many objects, each just under it, would multiply it. The
//! objects share a further budget, and a request that spends it ends with the
//! `number-of-matches-within-limits` truncation.

use super::hostile_content::calendar;
use crate::webdav::caldav_filter::{self, MAX_QUERY_WORK, MAX_REQUEST_WORK};
use crate::webdav::test_support::{MKCOL_CALENDAR, send_as_alice, test_app};
use axum::http::StatusCode;

/// One series that walks sixty thousand periods before the window.
fn series() -> String {
	"BEGIN:VEVENT\r\nDTSTART:20260101T000000Z\r\nRRULE:FREQ=DAILY;COUNT=60000;BYDAY=MO,TU,WE,TH,FR,SA,SU\r\nSUMMARY:decoy\r\nEND:VEVENT\r\n".to_string()
}

const QUERY: &str = "<C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:D=\"DAV:\"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"><C:time-range start=\"90000101T000000Z\" end=\"90010101T000000Z\"/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>";

/// What a search spends comes out of the budget it was given.
#[test]
fn a_search_spends_the_budget_it_is_given() {
	let filter = caldav_filter::parse(QUERY).expect("supported filter");
	let ics = calendar(&series());
	let mut left = MAX_QUERY_WORK;
	assert_eq!(
		caldav_filter::matches_within(&filter, &ics, &mut left),
		Ok(false)
	);
	assert!(left < MAX_QUERY_WORK - 50_000, "spent too little: {left}");
	// What is left is not enough for a second one.
	assert!(caldav_filter::matches_within(&filter, &ics, &mut left).is_err());
}

/// Objects that each fit their own bound, in a collection too big for the
/// request as a whole: the reply stops with the truncation on the collection
/// instead of searching every one of them.
#[tokio::test]
async fn a_query_over_many_costly_objects_stops_at_the_request_budget() {
	let dir = tempfile::tempdir().unwrap();
	let app = test_app(dir.path());
	let (status, _) = send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	assert_eq!(status, StatusCode::CREATED);
	// Each object costs more than its own bound, so each one spends the
	// whole of what it is granted.
	let objects = 2 * MAX_REQUEST_WORK / MAX_QUERY_WORK;
	let body = calendar(&series().repeat(2));
	for index in 0..objects {
		let (status, _) = send_as_alice(
			&app,
			"PUT",
			&format!("/cal/{index}.ics"),
			&[],
			body.as_bytes(),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED);
	}
	let (status, text) =
		send_as_alice(&app, "REPORT", "/cal", &[("Depth", "1")], QUERY.as_bytes()).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert!(
		text.contains("<D:number-of-matches-within-limits/>"),
		"the request was not cut short: {text}"
	);
	let answered = text.matches("507 Insufficient Storage").count();
	assert!(
		answered <= MAX_REQUEST_WORK / MAX_QUERY_WORK + 2,
		"{answered} of {objects} objects were searched"
	);
}
