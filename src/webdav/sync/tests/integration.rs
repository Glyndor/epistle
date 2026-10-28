//! End-to-end `sync-collection` (RFC 6578) and change-tag tests through the
//! WebDAV handler, for calendars and addressbooks.

use axum::Router;
use axum::http::StatusCode;

use crate::webdav::test_support::{
	MKCOL_ADDRESSBOOK, MKCOL_CALENDAR, send_as_alice, test_app, test_app_with_quota,
};

const EVENT: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T100000Z\r\nSUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const VCARD: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEND:VCARD\r\n";

const ETAG_ONLY: &str = "<D:prop><D:getetag/></D:prop>";

async fn calendar(dir: &std::path::Path, events: &[&str]) -> Router {
	calendar_on(test_app(dir), events).await
}

async fn calendar_on(app: Router, events: &[&str]) -> Router {
	let (status, _) = send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	assert_eq!(status, StatusCode::CREATED);
	for name in events {
		put(&app, &format!("/cal/{name}"), EVENT).await;
	}
	app
}

async fn put(app: &Router, path: &str, body: &[u8]) {
	let (status, _) = send_as_alice(app, "PUT", path, &[], body).await;
	assert!(status.is_success(), "PUT {path}: {status}");
}

async fn sync_with(app: &Router, path: &str, depth: &str, body: &str) -> (StatusCode, String) {
	send_as_alice(app, "REPORT", path, &[("Depth", depth)], body.as_bytes()).await
}

/// A `sync-collection` REPORT on `path` from `token` (empty for a first
/// sync) asking for `prop`.
async fn sync(app: &Router, path: &str, token: &str, prop: &str) -> (StatusCode, String) {
	let body = format!(
		"<D:sync-collection xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:sync-token>{token}</D:sync-token><D:sync-level>1</D:sync-level>{prop}</D:sync-collection>"
	);
	sync_with(app, path, "0", &body).await
}

/// The `DAV:sync-token` that is a direct child of the multistatus: the
/// last element before `</D:multistatus>`.
fn final_token(body: &str) -> String {
	let tail = body
		.trim_end()
		.strip_suffix("</D:multistatus>")
		.expect("multistatus")
		.trim_end();
	let tail = tail.strip_suffix("</D:sync-token>").expect("token last");
	let start = tail.rfind("<D:sync-token>").expect("token open") + "<D:sync-token>".len();
	tail[start..].to_string()
}

/// The `<D:response>` blocks of a multistatus.
fn responses(body: &str) -> Vec<&str> {
	body.split("<D:response>").skip(1).collect()
}

#[tokio::test]
async fn empty_token_lists_every_member_then_the_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &["a.ics", "b.ics"]).await;
	let (status, body) = sync(&app, "/cal", "", ETAG_ONLY).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let found = responses(&body);
	assert_eq!(
		found.len(),
		2,
		"one response per member, none for the collection"
	);
	assert!(found[0].contains("<D:href>/cal/a.ics</D:href>") && found[0].contains("<D:getetag>"));
	assert!(found[1].contains("<D:href>/cal/b.ics</D:href>"));
	assert!(final_token(&body).starts_with("urn:epistle:sync:"));
	assert!(!body.contains("calendar-data"), "not requested");
}

#[tokio::test]
async fn sync_from_a_token_returns_exactly_the_put_and_the_delete() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &["a.ics", "b.ics"]).await;
	let (_, first) = sync(&app, "/cal", "", ETAG_ONLY).await;
	let token = final_token(&first);
	put(&app, "/cal/c.ics", EVENT).await;
	let (status, _) = send_as_alice(&app, "DELETE", "/cal/a.ics", &[], b"").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (status, body) = sync(&app, "/cal", &token, ETAG_ONLY).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let found = responses(&body);
	assert_eq!(found.len(), 2, "only the two changes");
	let added = found
		.iter()
		.find(|r| r.contains("/cal/c.ics"))
		.expect("c.ics");
	assert!(added.contains("<D:getetag>") && added.contains("HTTP/1.1 200 OK"));
	let removed = found
		.iter()
		.find(|r| r.contains("/cal/a.ics"))
		.expect("a.ics");
	assert!(removed.contains("<D:status>HTTP/1.1 404 Not Found</D:status>"));
	assert!(
		!removed.contains("propstat"),
		"a removed member has a bare status"
	);
	assert_ne!(final_token(&body), token);
	let (_, again) = sync(&app, "/cal", &final_token(&body), ETAG_ONLY).await;
	assert!(responses(&again).is_empty(), "nothing changed since");
}

#[tokio::test]
async fn data_is_returned_when_asked_for() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &["a.ics"]).await;
	let prop = "<D:prop><D:getetag/><C:calendar-data/></D:prop>";
	let (_, body) = sync(&app, "/cal", "", prop).await;
	assert!(body.contains("SUMMARY:One"));
}

#[tokio::test]
async fn hrefs_are_percent_encoded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[]).await;
	put(&app, "/cal/a%20%26b.ics", EVENT).await;
	let (_, body) = sync(&app, "/cal", "", ETAG_ONLY).await;
	assert!(body.contains("<D:href>/cal/a%20%26b.ics</D:href>"));
}

#[tokio::test]
async fn garbage_expired_and_foreign_tokens_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[]).await;
	let (_, empty) = sync(&app, "/cal", "", ETAG_ONLY).await;
	let oldest = final_token(&empty);
	let coll = dir.path().join("accounts/alice/dav/cal");
	for i in 0..=super::MAX_ENTRIES {
		super::record(&coll, &[(format!("{i}.ics"), false)]).await;
	}
	let (_, recent) = sync(&app, "/cal", "", ETAG_ONLY).await;
	let recent = final_token(&recent);
	let refused = |token: String| {
		let app = app.clone();
		async move {
			let (status, body) = sync(&app, "/cal", &token, ETAG_ONLY).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "accepted {token}");
			assert!(body.contains("<D:valid-sync-token/>"));
		}
	};
	for garbage in ["not-a-token", "urn:epistle:sync:"] {
		refused(garbage.to_string()).await;
	}
	// The first change after `oldest` is no longer in the log.
	refused(oldest).await;
	// Delete and recreate the calendar, then write more than before: the
	// token of the old calendar must not be read against the new one.
	send_as_alice(&app, "DELETE", "/cal", &[], b"").await;
	send_as_alice(&app, "MKCOL", "/cal", &[], MKCOL_CALENDAR).await;
	for i in 0..=super::MAX_ENTRIES + 2 {
		super::record(&coll, &[(format!("{i}.ics"), false)]).await;
	}
	refused(recent).await;
}

#[tokio::test]
async fn infinite_level_and_non_zero_depth_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = calendar(dir.path(), &[]).await;
	let infinite = "<D:sync-collection xmlns:D=\"DAV:\"><D:sync-token/>\
		<D:sync-level>infinite</D:sync-level><D:prop/></D:sync-collection>";
	let (status, body) = sync_with(&app, "/cal", "0", infinite).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(body.contains("<D:sync-traversal-supported/>"));
	let one = "<D:sync-collection xmlns:D=\"DAV:\"><D:sync-token/><D:prop/></D:sync-collection>";
	let (status, _) = sync_with(&app, "/cal", "1", one).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_get_distinct_sequences() {
	let dir = tempfile::tempdir().expect("tempdir");
	// No quota, so no account lock stands between the writes: only the
	// collection's own lock keeps their log entries apart.
	let app = calendar_on(test_app_with_quota(dir.path(), Some(0)), &[]).await;
	let (_, before) = sync(&app, "/cal", "", ETAG_ONLY).await;
	let mut writes = tokio::task::JoinSet::new();
	for i in 0..16 {
		let app = app.clone();
		writes.spawn(async move { put(&app, &format!("/cal/{i}.ics"), EVENT).await });
	}
	while let Some(done) = writes.join_next().await {
		done.expect("write task");
	}
	let (status, body) = sync(&app, "/cal", &final_token(&before), ETAG_ONLY).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(responses(&body).len(), 16, "every write is in the log");
}

#[tokio::test]
async fn addressbook_syncs_and_plain_collection_does_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/book", &[], MKCOL_ADDRESSBOOK).await;
	put(&app, "/book/a.vcf", VCARD).await;
	let prop =
		"<D:prop><D:getetag/><C:address-data xmlns:C=\"urn:ietf:params:xml:ns:carddav\"/></D:prop>";
	let (status, body) = sync(&app, "/book", "", prop).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert!(body.contains("/book/a.vcf") && body.contains("Ada Lovelace"));
	send_as_alice(&app, "MKCOL", "/plain", &[], b"").await;
	let (status, body) = sync(&app, "/plain", "", ETAG_ONLY).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(body.contains("<D:supported-report/>"));
}
