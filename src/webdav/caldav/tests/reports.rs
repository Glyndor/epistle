//! REPORT, free-busy and scheduling Outbox requests against a calendar.

use super::base::{EVENT, MKCOL_CALENDAR, RECURRING, alice, bob, send, test_app};
use axum::http::{StatusCode, header};

#[tokio::test]
async fn multiget_returns_requested_events() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	let report = "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:href>/cal/e1.ics</D:href></C:calendar-multiget>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 1);
	assert!(text.contains("/cal/e1.ics"));
	assert!(text.contains("<C:calendar-data>"));
	assert!(text.contains("<D:getetag>"));
}

#[tokio::test]
async fn query_returns_all_events() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	send(&app, "PUT", "/cal/r1.ics", Some(&alice()), &[], RECURRING).await;
	let report = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/><C:calendar-data/></D:prop></C:calendar-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<C:calendar-data>").count(), 2);
}

#[tokio::test]
async fn free_busy_query_covers_recurring_instances() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/r1.ics", Some(&alice()), &[], RECURRING).await;
	let report = "<C:free-busy-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<C:time-range start=\"20260101T000000Z\" end=\"20260201T000000Z\"/></C:free-busy-query>";
	let (status, body, headers) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/calendar");
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("BEGIN:VFREEBUSY"));
	// Three daily instances, each an hour long.
	assert_eq!(text.matches("FREEBUSY;FBTYPE=BUSY:").count(), 3);
	assert!(text.contains("20260101T080000Z/20260101T090000Z"));
	assert!(text.contains("20260103T080000Z/20260103T090000Z"));
}

#[tokio::test]
async fn free_busy_query_without_range_is_bad_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let report = "<C:free-busy-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\"/>";
	let (status, _, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn report_bad_body_is_bad_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let (status, _, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[],
		b"<D:principal-property-search xmlns:D=\"DAV:\"/>",
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn multiget_traversal_href_is_not_served() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	let report = "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:href>/../../bob/dav/secret.ics</D:href>\
		<D:href>/cal/../../../bob/dav/secret.ics</D:href></C:calendar-multiget>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 0);
}

#[tokio::test]
async fn report_account_isolation_holds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&bob()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/secret.ics", Some(&bob()), &[], EVENT).await;
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let report = "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:href>/cal/secret.ics</D:href></C:calendar-multiget>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 0);
}

#[tokio::test]
async fn report_unauthenticated_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(
		&app,
		"REPORT",
		"/cal",
		None,
		&[],
		b"<C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\"/>",
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn propfind_discovery_returns_calendar_home_and_scheduling() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let body = "<D:propfind xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:current-user-principal/><C:calendar-home-set/>\
		<C:schedule-outbox-URL/><C:schedule-inbox-URL/></D:prop></D:propfind>";
	let (status, out, _) = send(
		&app,
		"PROPFIND",
		"/alice/",
		Some(&alice()),
		&[("Depth", "0".to_string())],
		body.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("<CAL:calendar-home-set>"));
	assert!(text.contains("<CAL:schedule-outbox-URL>"));
	assert!(text.contains("<CAL:schedule-inbox-URL>"));
	assert!(text.contains("/alice/outbox/"));
	assert!(text.contains("/alice/inbox/"));
}

#[tokio::test]
async fn outbox_post_returns_account_busy_periods() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	send(&app, "PUT", "/cal/r1.ics", Some(&alice()), &[], RECURRING).await;
	let request = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\n\
		DTSTART:20260101T000000Z\r\nDTEND:20260201T000000Z\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
	let (status, body, headers) = send(
		&app,
		"POST",
		"/outbox/",
		Some(&alice()),
		&[],
		request.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/calendar");
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("BEGIN:VFREEBUSY"));
	// One single event plus three recurring instances = four busy periods.
	assert_eq!(text.matches("FREEBUSY;FBTYPE=BUSY:").count(), 4);
}

#[tokio::test]
async fn outbox_post_without_range_is_bad_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let request = "BEGIN:VCALENDAR\r\nBEGIN:VFREEBUSY\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
	let (status, _, _) = send(
		&app,
		"POST",
		"/outbox/",
		Some(&alice()),
		&[],
		request.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_outside_outbox_is_method_not_allowed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "POST", "/notbox/", Some(&alice()), &[], b"x").await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn post_unauthenticated_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "POST", "/outbox/", None, &[], b"x").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}
