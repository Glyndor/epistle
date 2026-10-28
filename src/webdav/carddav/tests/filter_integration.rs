//! End-to-end `addressbook-query` filter tests (RFC 6352 §10.5), driven
//! through the WebDAV handler. The parser and matcher have their own unit
//! tests in `src/webdav/carddav_filter/tests/base.rs`.

use axum::Router;
use axum::http::StatusCode;

use crate::webdav::test_support::{MKCOL_ADDRESSBOOK, send_as_alice, test_app};

const CARD_ADA: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.org\r\nEMAIL:ada@personal.example.org\r\nEND:VCARD\r\n";

const CARD_BABBAGE: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Charles Babbage\r\nEMAIL:charles@example.org\r\nEND:VCARD\r\n";

const CARD_NO_EMAIL: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Anon Ymous\r\nEND:VCARD\r\n";

/// An addressbook at `/book` holding Ada (`a.vcf`), Babbage (`b.vcf`) and a
/// card without any EMAIL (`c.vcf`).
async fn book(dir: &std::path::Path) -> Router {
	let app = test_app(dir);
	let (status, _) = send_as_alice(&app, "MKCOL", "/book", &[], MKCOL_ADDRESSBOOK).await;
	assert_eq!(status, StatusCode::CREATED);
	for (name, card) in [("a", CARD_ADA), ("b", CARD_BABBAGE), ("c", CARD_NO_EMAIL)] {
		let path = format!("/book/{name}.vcf");
		let (status, _) = send_as_alice(&app, "PUT", &path, &[], card).await;
		assert_eq!(status, StatusCode::CREATED);
	}
	app
}

/// Run an `addressbook-query` whose `<CR:filter>` is `filter` and return the
/// sorted list of card names (`a`, `b`, `c`) in the answer.
async fn query(app: &Router, filter: &str) -> (StatusCode, Vec<&'static str>, String) {
	let body = format!(
		"<CR:addressbook-query xmlns:D=\"DAV:\" xmlns:CR=\"urn:ietf:params:xml:ns:carddav\">\
		<D:prop><D:getetag/><CR:address-data/></D:prop>{filter}</CR:addressbook-query>"
	);
	let (status, text) =
		send_as_alice(app, "REPORT", "/book", &[("Depth", "1")], body.as_bytes()).await;
	let names = ["a", "b", "c"]
		.into_iter()
		.filter(|name| text.contains(&format!("/book/{name}.vcf")))
		.collect();
	(status, names, text)
}

#[tokio::test]
async fn email_contains_match_returns_only_matching_cards() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = book(dir.path()).await;
	let (status, names, _) = query(
		&app,
		"<CR:filter><CR:prop-filter name=\"EMAIL\">\
		<CR:text-match collation=\"i;unicode-casemap\" match-type=\"contains\">PERSONAL</CR:text-match>\
		</CR:prop-filter></CR:filter>",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(names, ["a"], "only Ada has a personal address");
}

#[tokio::test]
async fn anyof_and_allof_combine_prop_filters_differently() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = book(dir.path()).await;
	let filters = "<CR:prop-filter name=\"EMAIL\">\
		<CR:text-match match-type=\"ends-with\">@example.org</CR:text-match>\
		</CR:prop-filter>\
		<CR:prop-filter name=\"FN\">\
		<CR:text-match match-type=\"starts-with\">charles</CR:text-match>\
		</CR:prop-filter>";
	let (_, anyof, _) = query(
		&app,
		&format!("<CR:filter test=\"anyof\">{filters}</CR:filter>"),
	)
	.await;
	let (_, allof, _) = query(
		&app,
		&format!("<CR:filter test=\"allof\">{filters}</CR:filter>"),
	)
	.await;
	assert_eq!(anyof, ["a", "b"], "anyof: either prop-filter is enough");
	assert_eq!(allof, ["b"], "allof: only Babbage passes both");
}

#[tokio::test]
async fn negate_condition_inverts_the_text_match() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = book(dir.path()).await;
	let (status, names, _) = query(
		&app,
		"<CR:filter><CR:prop-filter name=\"EMAIL\">\
		<CR:text-match negate-condition=\"yes\" match-type=\"contains\">personal</CR:text-match>\
		</CR:prop-filter></CR:filter>",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	// Ada has a personal address, so the negated match excludes her; the
	// card without any EMAIL has no property to test and is excluded too.
	assert_eq!(names, ["b"]);
}

#[tokio::test]
async fn is_not_defined_selects_cards_without_the_property() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = book(dir.path()).await;
	let (_, names, _) = query(
		&app,
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:is-not-defined/></CR:prop-filter></CR:filter>",
	)
	.await;
	assert_eq!(names, ["c"]);
}

#[tokio::test]
async fn unsupported_filter_element_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = book(dir.path()).await;
	let (status, names, text) = query(
		&app,
		"<CR:filter><CR:prop-filter name=\"EMAIL\"><CR:param-filter name=\"TYPE\"/></CR:prop-filter></CR:filter>",
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(names.is_empty());
	assert!(
		text.contains("<C:supported-filter/>") && text.contains("urn:ietf:params:xml:ns:carddav"),
		"403 must carry the CARDDAV:supported-filter precondition"
	);
}
