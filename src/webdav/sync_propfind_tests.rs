//! What PROPFIND tells a client about a calendar or addressbook so it can
//! sync incrementally: `DAV:sync-token`, `CS:getctag`, the reports in
//! `DAV:supported-report-set`, and no internal bookkeeping files.

use axum::Router;
use axum::http::StatusCode;

use crate::webdav::test_support::{MKCOL_ADDRESSBOOK, MKCOL_CALENDAR, send_as_alice, test_app};

const EVENT: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20260115T090000Z\r\nSUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

async fn propfind(app: &Router, path: &str, depth: &str) -> String {
	let (status, body) = send_as_alice(app, "PROPFIND", path, &[("Depth", depth)], b"").await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	body
}

/// The text of the first `<{open}...>VALUE</{close}>` in `body`.
fn value_of<'a>(body: &'a str, open: &str, close: &str) -> &'a str {
	let start = body.find(open).expect(open);
	let after = &body[start..];
	let after = &after[after.find('>').expect("tag end") + 1..];
	&after[..after.find(close).expect(close)]
}

fn ctag(body: &str) -> String {
	value_of(body, "<CS:getctag", "</CS:getctag>").to_string()
}

#[tokio::test]
async fn getctag_and_sync_token_change_on_every_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	let mut seen = vec![ctag(&propfind(&app, "/cal", "0").await)];
	for (method, path) in [
		("PUT", "/cal/a.ics"),
		("PUT", "/cal/a.ics"),
		("DELETE", "/cal/a.ics"),
	] {
		let (status, _) = send_as_alice(&app, method, path, &[], EVENT).await;
		assert!(status.is_success());
		let body = propfind(&app, "/cal", "0").await;
		let tag = ctag(&body);
		assert!(!seen.contains(&tag), "{method} did not change the ctag");
		assert_eq!(value_of(&body, "<D:sync-token", "</D:sync-token>"), tag);
		seen.push(tag);
	}
}

#[tokio::test]
async fn supported_report_set_lists_the_collection_reports() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	send_as_alice(&app, "MKCOL", "/book", &[], MKCOL_ADDRESSBOOK).await;
	send_as_alice(&app, "MKCOL", "/plain", &[], b"").await;
	let cal = propfind(&app, "/cal", "0").await;
	for report in [
		"D:sync-collection",
		"CAL:calendar-query",
		"CAL:calendar-multiget",
	] {
		assert!(
			cal.contains(&format!("<D:report><{report}/></D:report>")),
			"{report}"
		);
	}
	let book = propfind(&app, "/book", "0").await;
	for report in [
		"D:sync-collection",
		"C:addressbook-query",
		"C:addressbook-multiget",
	] {
		assert!(
			book.contains(&format!("<D:report><{report}/></D:report>")),
			"{report}"
		);
	}
	let plain = propfind(&app, "/plain", "0").await;
	assert!(!plain.contains("supported-report-set") && !plain.contains("getctag"));
}

#[tokio::test]
async fn the_change_log_is_not_listed_as_a_member() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	send_as_alice(&app, "PUT", "/cal/a.ics", &[], EVENT).await;
	let listing = propfind(&app, "/cal", "1").await;
	assert!(listing.contains("/cal/a.ics"));
	assert!(!listing.contains("changelog"));
}

#[tokio::test]
async fn the_change_log_cannot_be_read_or_replaced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	send_as_alice(&app, "PUT", "/cal/a.ics", &[], EVENT).await;
	let before = propfind(&app, "/cal", "0").await;
	for method in ["GET", "PUT", "DELETE"] {
		let (status, _) = send_as_alice(&app, method, "/cal/.changelog", &[], b"forged").await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
	}
	let dest = [("Destination", "/cal/.changelog")];
	let (status, _) = send_as_alice(&app, "COPY", "/cal/a.ics", &dest, b"").await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let after = propfind(&app, "/cal", "0").await;
	assert_eq!(ctag(&after), ctag(&before), "the log is untouched");
}
