//! The bounds on a whole `REPORT`, through the CalDAV and CardDAV handlers.

use axum::http::StatusCode;

use crate::webdav::{caldav, carddav};

use super::{MAX_FILTER_BODY, MAX_REPORT_BYTES, MAX_REPORT_HREFS, MAX_RESOURCE_BYTES};

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

fn root() -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	(dir, root)
}

fn file_of(path: std::path::PathBuf, len: u64, byte: u8) {
	std::fs::write(path, vec![byte; len as usize]).expect("write");
}

#[tokio::test]
async fn a_multiget_naming_too_many_distinct_hrefs_is_refused() {
	let (_dir, root) = root();
	let many = (0..=MAX_REPORT_HREFS).map(|n| format!("/e{n}.ics"));
	let (status, body) =
		text(caldav::report(&root, &root, calendar_multiget(many).as_bytes()).await).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert!(body.contains("number-of-matches-within-limits"));
	let many = (0..=MAX_REPORT_HREFS).map(|n| format!("/c{n}.vcf"));
	let response = carddav::report(&root, &root, card_multiget(many).as_bytes()).await;
	assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_resource_named_twice_is_answered_once() {
	let (_dir, root) = root();
	std::fs::write(root.join("a.ics"), b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").expect("write");
	std::fs::write(root.join("a.vcf"), b"BEGIN:VCARD\r\nEND:VCARD\r\n").expect("write");
	let mut spellings: Vec<String> = (0..5 * MAX_REPORT_HREFS)
		.map(|_| "/a.ics".to_string())
		.collect();
	spellings.extend(["/./a.ics", "//a.ics", "/%61.ics"].map(String::from));
	let (status, body) = text(
		caldav::report(
			&root,
			&root,
			calendar_multiget(spellings.into_iter()).as_bytes(),
		)
		.await,
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("<D:response>").count(), 1);
	let repeated = (0..5 * MAX_REPORT_HREFS).map(|_| "/a.vcf".to_string());
	let (status, body) =
		text(carddav::report(&root, &root, card_multiget(repeated).as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("<D:response>").count(), 1);
}

/// The biggest stored resource, made of the byte that grows most when
/// escaped, is returned on its own and complete.
#[tokio::test]
async fn the_largest_stored_resource_is_returned_whole() {
	let (_dir, root) = root();
	file_of(root.join("big.ics"), MAX_RESOURCE_BYTES, b'"');
	file_of(root.join("big.vcf"), MAX_RESOURCE_BYTES, b'"');
	let once = ["/big.ics".to_string()].into_iter();
	let (status, body) =
		text(caldav::report(&root, &root, calendar_multiget(once).as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	// The quotes of the etag add two.
	assert_eq!(
		body.matches("&quot;").count() as u64,
		MAX_RESOURCE_BYTES + 2
	);
	assert!(body.len() as u64 <= MAX_REPORT_BYTES);
	let once = ["/big.vcf".to_string()].into_iter();
	let (status, body) =
		text(carddav::report(&root, &root, card_multiget(once).as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	// The quotes of the etag add two.
	assert_eq!(
		body.matches("&quot;").count() as u64,
		MAX_RESOURCE_BYTES + 2
	);
}

/// Seven resources of the largest stored size do not fit one reply: the ones
/// that fit are returned and the rest are answered `507` by name.
#[tokio::test]
async fn a_multiget_that_outgrows_the_reply_answers_the_rest_with_507() {
	let (_dir, root) = root();
	let names: Vec<String> = (0..7).map(|n| format!("/e{n}.ics")).collect();
	for name in &names {
		file_of(root.join(&name[1..]), MAX_RESOURCE_BYTES, b'x');
	}
	let (status, body) = text(
		caldav::report(
			&root,
			&root,
			calendar_multiget(names.clone().into_iter()).as_bytes(),
		)
		.await,
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("200 OK").count(), 6);
	assert_eq!(body.matches("507 Insufficient Storage").count(), 1);
	assert!(body.contains("<D:href>/e6.ics</D:href>\n\t\t<D:status>HTTP/1.1 507"));
	assert!(body.len() as u64 <= MAX_REPORT_BYTES + 4096);
}

/// A query that outgrows the reply keeps what fitted and ends with the
/// truncation condition on the collection; it never drops a match quietly.
#[tokio::test]
async fn a_query_that_outgrows_the_reply_says_it_was_cut() {
	let (_dir, root) = root();
	for n in 0..7 {
		file_of(root.join(format!("e{n}.ics")), MAX_RESOURCE_BYTES, b'x');
		file_of(root.join(format!("c{n}.vcf")), MAX_RESOURCE_BYTES, b'x');
	}
	let query = format!("<C:calendar-query xmlns:C=\"{}\"/>", caldav::CALDAV_NS);
	let (status, body) = text(caldav::report(&root, &root, query.as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("200 OK").count(), 6);
	assert!(body.contains("<D:number-of-matches-within-limits/>"));
	let query = format!("<C:addressbook-query xmlns:C=\"{}\"/>", carddav::CARDDAV_NS);
	let (status, body) = text(carddav::report(&root, &root, query.as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("200 OK").count(), 6);
	assert!(body.contains("<D:number-of-matches-within-limits/>"));
}

/// A file too long for any reply (one stored before the limit on a resource,
/// or moved in from elsewhere) is listed with its own `507`, not skipped.
#[tokio::test]
async fn a_file_longer_than_any_reply_is_answered_507_not_skipped() {
	let (_dir, root) = root();
	std::fs::write(
		root.join("small.ics"),
		b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
	)
	.expect("write");
	let huge = std::fs::File::create(root.join("huge.ics")).expect("create");
	huge.set_len(MAX_REPORT_BYTES + 1).expect("sparse");
	let query = format!("<C:calendar-query xmlns:C=\"{}\"/>", caldav::CALDAV_NS);
	let (status, body) = text(caldav::report(&root, &root, query.as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert!(body.contains("/small.ics"));
	assert!(body.contains("<D:href>/huge.ics</D:href>\n\t\t<D:status>HTTP/1.1 507"));
	let once = ["/huge.ics".to_string()].into_iter();
	let (status, body) =
		text(caldav::report(&root, &root, calendar_multiget(once).as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert!(body.contains("<D:href>/huge.ics</D:href>\n\t\t<D:status>HTTP/1.1 507"));
}

#[tokio::test]
async fn a_query_or_free_busy_body_over_the_cap_is_refused() {
	let (_dir, root) = root();
	let pad = " ".repeat(MAX_FILTER_BODY);
	for body in [
		format!("<C:calendar-query xmlns:C=\"x\">{pad}</C:calendar-query>"),
		format!("<C:free-busy-query xmlns:C=\"x\">{pad}</C:free-busy-query>"),
	] {
		let (status, text) = text(caldav::report(&root, &root, body.as_bytes()).await).await;
		assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
		assert!(text.contains("number-of-matches-within-limits"));
	}
	let body = format!("<C:addressbook-query xmlns:C=\"x\">{pad}</C:addressbook-query>");
	let response = carddav::report(&root, &root, body.as_bytes()).await;
	assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A request that names only `getetag` gets no content, and an object with a
/// character XML cannot carry does not spoil the reply for the others.
#[tokio::test]
async fn etag_only_requests_get_no_data_and_dirty_objects_stay_well_formed() {
	let (_dir, root) = root();
	std::fs::write(
		root.join("a.ics"),
		b"BEGIN:VCALENDAR\r\nX:\x0b\r\nEND:VCALENDAR\r\n",
	)
	.expect("write");
	std::fs::write(root.join("b.ics"), b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").expect("write");
	let etags = format!(
		"<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"{}\"><D:prop><D:getetag/></D:prop></C:calendar-query>",
		caldav::CALDAV_NS
	);
	let (status, body) = text(caldav::report(&root, &root, etags.as_bytes()).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("<D:getetag>").count(), 2);
	assert!(!body.contains("calendar-data"));
	let full = format!(
		"<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"{}\"><D:prop><D:getetag/><C:calendar-data/></D:prop></C:calendar-query>",
		caldav::CALDAV_NS
	);
	let (_, body) = text(caldav::report(&root, &root, full.as_bytes()).await).await;
	assert_eq!(body.matches("<C:calendar-data>").count(), 2);
	assert!(!body.contains('\u{b}'));
	assert!(body.contains("X:\u{fffd}&#13;"));
	let once = ["/a.ics".to_string()].into_iter();
	let ask = calendar_multiget(once).replace(
		"</C:calendar-multiget>",
		"<D:prop><D:getetag/></D:prop></C:calendar-multiget>",
	);
	let (_, body) = text(caldav::report(&root, &root, ask.as_bytes()).await).await;
	assert!(!body.contains("calendar-data"));
}
