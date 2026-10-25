//! The bounds on a whole `REPORT`, through the CalDAV and CardDAV handlers.

use axum::http::StatusCode;

use crate::webdav::{caldav, carddav};

use super::{MAX_FILTER_BODY, MAX_REPORT_BYTES, MAX_REPORT_HREFS};

async fn text(response: axum::response::Response) -> (StatusCode, String) {
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
		.await
		.expect("body");
	(status, String::from_utf8_lossy(&bytes).into_owned())
}

fn multiget(ns: &str, kind: &str, hrefs: impl Iterator<Item = String>) -> String {
	let list: String = hrefs.map(|h| format!("<D:href>{h}</D:href>")).collect();
	format!("<C:{kind} xmlns:D=\"DAV:\" xmlns:C=\"{ns}\">{list}</C:{kind}>")
}

fn calendar_multiget(hrefs: impl Iterator<Item = String>) -> String {
	multiget(caldav::CALDAV_NS, "calendar-multiget", hrefs)
}

fn card_multiget(hrefs: impl Iterator<Item = String>) -> String {
	multiget(carddav::CARDDAV_NS, "addressbook-multiget", hrefs)
}

#[tokio::test]
async fn a_multiget_naming_too_many_distinct_hrefs_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	let many = (0..=MAX_REPORT_HREFS).map(|n| format!("/e{n}.ics"));
	let response = caldav::report(&root, &root, calendar_multiget(many).as_bytes()).await;
	assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
	let many = (0..=MAX_REPORT_HREFS).map(|n| format!("/c{n}.vcf"));
	let response = carddav::report(&root, &root, card_multiget(many).as_bytes()).await;
	assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_repeated_href_is_answered_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	std::fs::write(root.join("a.ics"), b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").expect("write");
	std::fs::write(root.join("a.vcf"), b"BEGIN:VCARD\r\nEND:VCARD\r\n").expect("write");
	let repeated = (0..5 * MAX_REPORT_HREFS).map(|_| "/a.ics".to_string());
	let (status, body) =
		text(caldav::report(&root, &root, calendar_multiget(repeated).as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("<D:response>").count(), 1);
	let repeated = (0..5 * MAX_REPORT_HREFS).map(|_| "/a.vcf".to_string());
	let (status, body) =
		text(carddav::report(&root, &root, card_multiget(repeated).as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("<D:response>").count(), 1);
}

/// A file just over half the reply budget, so two names for it overflow it.
fn big_file(path: &std::path::Path) {
	std::fs::write(path, vec![b'x'; MAX_REPORT_BYTES as usize / 2 + 1]).expect("write");
}

#[tokio::test]
async fn a_multiget_reply_over_the_byte_budget_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	big_file(&root.join("a.ics"));
	big_file(&root.join("a.vcf"));
	let twice = ["/a.ics", "/./a.ics"].map(String::from).into_iter();
	let response = caldav::report(&root, &root, calendar_multiget(twice).as_bytes()).await;
	assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
	let twice = ["/a.vcf", "/./a.vcf"].map(String::from).into_iter();
	let response = carddav::report(&root, &root, card_multiget(twice).as_bytes()).await;
	assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
	let once = ["/a.ics".to_string()].into_iter();
	let response = caldav::report(&root, &root, calendar_multiget(once).as_bytes()).await;
	assert_eq!(response.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn a_query_reply_over_the_byte_budget_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	for name in ["a.ics", "b.ics"] {
		big_file(&root.join(name));
	}
	for name in ["a.vcf", "b.vcf"] {
		big_file(&root.join(name));
	}
	let query = format!("<C:calendar-query xmlns:C=\"{}\"/>", caldav::CALDAV_NS);
	let response = caldav::report(&root, &root, query.as_bytes()).await;
	assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
	let query = format!("<C:addressbook-query xmlns:C=\"{}\"/>", carddav::CARDDAV_NS);
	let response = carddav::report(&root, &root, query.as_bytes()).await;
	assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn a_query_or_free_busy_body_over_the_cap_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	let pad = " ".repeat(MAX_FILTER_BODY);
	for body in [
		format!("<C:calendar-query xmlns:C=\"x\">{pad}</C:calendar-query>"),
		format!("<C:free-busy-query xmlns:C=\"x\">{pad}</C:free-busy-query>"),
	] {
		let response = caldav::report(&root, &root, body.as_bytes()).await;
		assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
	}
	let body = format!("<C:addressbook-query xmlns:C=\"x\">{pad}</C:addressbook-query>");
	let response = carddav::report(&root, &root, body.as_bytes()).await;
	assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
