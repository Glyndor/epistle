//! Entry point for the fuzz target of the WebDAV request bodies that are not
//! filters (see `crate::fuzzing`): the href list of a multiget, the
//! discovery check of a PROPFIND, the data check of a report and the
//! `sync-collection` request with its level and token.

use super::caldav_filter_xml::first_open;
use super::{caldav_hrefs, carddav, propfind, report_bounds, sync, sync_report};

/// Every reader of a REPORT or PROPFIND body that runs before a filter.
///
/// # Panics
///
/// When a reader breaks what it promises. That is what the fuzz target
/// looks for.
pub(crate) fn report_body_for_fuzzing(body: &str) {
	let hrefs = caldav_hrefs::hrefs(body).collect::<Vec<_>>();
	// The CardDAV report reads its hrefs with its own copy of the scanner;
	// the two must agree.
	assert_eq!(
		hrefs,
		carddav::hrefs(body).collect::<Vec<_>>(),
		"CalDAV and CardDAV hrefs differ"
	);
	// `<href>` and one byte of value is the shortest href a body can carry.
	assert!(hrefs.len() <= body.len() / 7, "{} hrefs", hrefs.len());
	for href in &hrefs {
		assert!(!href.is_empty() && href.trim() == href, "untrimmed href");
		assert!(!href.contains('<'), "href runs into the next tag");
	}
	if let Some(at) = caldav_hrefs::find_open(body, "href") {
		assert_eq!(body.as_bytes()[at], b'<', "match not on a tag");
	}
	std::hint::black_box(propfind::wants_discovery(body));
	for data in ["calendar-data", "address-data"] {
		std::hint::black_box(report_bounds::wants_data(body, data));
	}
	if sync_report::is_sync_collection(body) {
		assert!(first_open(body, "sync-collection").is_some());
	}
	std::hint::black_box(sync_report::level(body));
	let token = sync_report::requested_token(body);
	if let Some(token) = &token {
		assert!(!token.is_empty(), "an empty token is a first sync");
	}
	sync::log_and_token_for_fuzzing(body, token.as_deref().unwrap_or(body));
}
