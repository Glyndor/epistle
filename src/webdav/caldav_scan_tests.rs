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
