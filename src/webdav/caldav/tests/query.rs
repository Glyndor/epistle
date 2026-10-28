//! `calendar-query` filter semantics through the WebDAV handler (RFC 4791
//! §9.7 and §9.9): open-ended and overlapping time ranges, all-day events,
//! `is-not-defined` on a component, several comp-filters together, and the
//! shapes the server refuses with `CALDAV:supported-filter`.

use axum::Router;
use axum::http::StatusCode;

use crate::webdav::test_support::{MKCOL_CALENDAR, send_as_alice, test_app};

/// 2026-01-15 09:00 to 11:00 UTC: starts before a 10:00 window and ends
/// inside it.
const LONG: &str = "BEGIN:VEVENT\r\nUID:long\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T110000Z\r\nSUMMARY:Long\r\nEND:VEVENT\r\n";

/// An all-day event on 2026-01-15 without DTEND: it lasts the whole day.
const ALL_DAY: &str =
	"BEGIN:VEVENT\r\nUID:day\r\nDTSTART;VALUE=DATE:20260115\r\nSUMMARY:Holiday\r\nEND:VEVENT\r\n";

/// 2026-01-10 08:00 to 09:00 UTC, with two attendees.
const EARLY: &str = "BEGIN:VEVENT\r\nUID:early\r\nDTSTART:20260110T080000Z\r\nDTEND:20260110T090000Z\r\nATTENDEE:mailto:ada@example.org\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\n";

const TODO: &str = "BEGIN:VTODO\r\nUID:todo\r\nSUMMARY:Buy milk\r\nEND:VTODO\r\n";

/// A calendar at `/cal` with one object per entry of `objects`, each named
/// `<name>.ics` and wrapping the given components in a VCALENDAR.
async fn calendar(dir: &std::path::Path, objects: &[(&str, &[&str])]) -> Router {
	let app = test_app(dir);
	let (status, _) = send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	assert_eq!(status, StatusCode::CREATED);
	for (name, components) in objects {
		let body = format!(
			"BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{}END:VCALENDAR\r\n",
			components.concat()
		);
		let path = format!("/cal/{name}.ics");
		let (status, _) = send_as_alice(&app, "PUT", &path, &[], body.as_bytes()).await;
		assert_eq!(status, StatusCode::CREATED);
	}
	app
}

/// Run a calendar-query whose VCALENDAR comp-filter holds `inner`; return
/// the status, the object names found in the answer (in `names` order),
/// and the body.
async fn query(
	app: &Router,
	inner: &str,
	names: &[&'static str],
) -> (StatusCode, Vec<&'static str>, String) {
	let body = format!(
		"<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\">{inner}\
		</C:comp-filter></C:filter></C:calendar-query>"
	);
	let (status, text) =
		send_as_alice(app, "REPORT", "/cal", &[("Depth", "1")], body.as_bytes()).await;
	let found = names
		.iter()
		.copied()
		.filter(|name| text.contains(&format!("/cal/{name}.ics")))
		.collect();
	(status, found, text)
}

fn vevent_range(attrs: &str) -> String {
	format!("<C:comp-filter name=\"VEVENT\"><C:time-range {attrs}/></C:comp-filter>")
}

#[tokio::test]
async fn open_ended_time_range_is_honoured() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[("early", &[EARLY]), ("long", &[LONG])]).await;
	let names = ["early", "long"];
	let (_, after, _) = query(&app, &vevent_range("start=\"20260112T000000Z\""), &names).await;
	assert_eq!(after, ["long"], "start only: everything ending after it");
	let (_, before, _) = query(&app, &vevent_range("end=\"20260112T000000Z\""), &names).await;
	assert_eq!(before, ["early"], "end only: everything starting before it");
}

#[tokio::test]
async fn event_started_before_the_window_still_overlaps_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[("long", &[LONG]), ("early", &[EARLY])]).await;
	let range = vevent_range("start=\"20260115T100000Z\" end=\"20260115T120000Z\"");
	let (status, found, _) = query(&app, &range, &["long", "early"]).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(found, ["long"]);
}

#[tokio::test]
async fn all_day_event_covers_its_whole_day() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[("day", &[ALL_DAY])]).await;
	let noon = vevent_range("start=\"20260115T120000Z\" end=\"20260115T130000Z\"");
	let (_, found, _) = query(&app, &noon, &["day"]).await;
	assert_eq!(found, ["day"]);
	let next_day = vevent_range("start=\"20260116T000000Z\" end=\"20260116T010000Z\"");
	let (_, found, _) = query(&app, &next_day, &["day"]).await;
	assert!(found.is_empty(), "the day after is outside");
}

#[tokio::test]
async fn is_not_defined_on_a_component_excludes_objects_that_have_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(
		dir.path(),
		&[("event", &[EARLY]), ("mixed", &[EARLY, TODO])],
	)
	.await;
	let filter = "<C:comp-filter name=\"VTODO\"><C:is-not-defined/></C:comp-filter>";
	let (status, found, _) = query(&app, filter, &["event", "mixed"]).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(found, ["event"]);
}

#[tokio::test]
async fn sibling_comp_filters_must_all_match() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(
		dir.path(),
		&[("event", &[EARLY]), ("mixed", &[EARLY, TODO])],
	)
	.await;
	let filter = "<C:comp-filter name=\"VEVENT\"/><C:comp-filter name=\"VTODO\"/>";
	let (_, found, _) = query(&app, filter, &["event", "mixed"]).await;
	assert_eq!(found, ["mixed"]);
}

#[tokio::test]
async fn text_match_looks_at_every_instance_of_the_property() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[("early", &[EARLY]), ("long", &[LONG])]).await;
	let filter = "<C:comp-filter name=\"VEVENT\"><C:prop-filter name=\"ATTENDEE\">\
		<C:text-match>bob@</C:text-match></C:prop-filter></C:comp-filter>";
	let (_, found, _) = query(&app, filter, &["early", "long"]).await;
	assert_eq!(found, ["early"], "bob is the second ATTENDEE line");
}

#[tokio::test]
async fn unsupported_or_malformed_filters_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[("early", &[EARLY])]).await;
	for filter in [
		// A nested VALARM comp-filter.
		"<C:comp-filter name=\"VEVENT\"><C:comp-filter name=\"VALARM\">\
		<C:time-range start=\"20260101T000000Z\" end=\"20260102T000000Z\"/></C:comp-filter></C:comp-filter>",
		// A time-range on a property.
		"<C:comp-filter name=\"VEVENT\"><C:prop-filter name=\"DTSTAMP\">\
		<C:time-range start=\"20260101T000000Z\" end=\"20260102T000000Z\"/></C:prop-filter></C:comp-filter>",
		// A time-range that does not parse, and one with neither bound.
		&vevent_range("start=\"tomorrow\" end=\"20260102T000000Z\""),
		&vevent_range(""),
	] {
		let (status, found, text) = query(&app, filter, &["early"]).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "accepted: {filter}");
		assert!(found.is_empty());
		assert!(text.contains("<C:supported-filter/>"));
	}
}
