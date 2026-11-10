//! Linear-scan regression tests for the CalDAV REPORT body scan.

use std::sync::atomic::Ordering;

use super::*;

/// A 20 000-tag body must not push the scanner past a linear bound. See
/// `carddav_scan_tests::find_open_scans_a_20000_tag_body_in_linear_steps`
/// for the reasoning.
#[test]
fn caldav_find_open_scans_a_20000_tag_body_in_linear_steps() {
	let mut body = String::with_capacity(20_000 * 2);
	for _ in 0..20_000 {
		body.push_str("<a");
	}
	let body_len = body.len();
	SCAN_STEPS.store(0, Ordering::Relaxed);
	let _ = find_open(&body, "href");
	let steps = SCAN_STEPS.load(Ordering::Relaxed);
	assert!(
		steps <= 10 * body_len as u64,
		"caldav scan did {steps} steps on a {body_len}-byte body (linear bound {})",
		10 * body_len
	);
}

/// A multiget body reads its hrefs one at a time: asking for the first two of
/// a very long list does not walk the rest of the body.
#[test]
fn caldav_hrefs_are_read_lazily() {
	let list: String = (0..50_000)
		.map(|n| format!("<D:href>/e{n}.x</D:href>"))
		.collect();
	let body = format!("<C:multiget xmlns:D=\"DAV:\">{list}</C:multiget>");
	SCAN_STEPS.store(0, Ordering::Relaxed);
	let first: Vec<String> = hrefs(&body).take(2).collect();
	let steps = SCAN_STEPS.load(Ordering::Relaxed);
	assert_eq!(first, vec!["/e0.x", "/e1.x"]);
	assert!(
		steps < body.len() as u64 / 2,
		"reading two hrefs touched {steps} of {} bytes",
		body.len()
	);
}
