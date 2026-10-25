use super::*;
use std::time::{Duration, Instant};

#[test]
fn unescape_decodes_entities_and_keeps_the_rest() {
	assert_eq!(unescape("a &amp; b &lt;c&gt; &#65;&#x42;"), "a & b <c> AB");
	assert_eq!(unescape("a & b"), "a & b");
	assert_eq!(unescape("x &unknown; y"), "x &unknown; y");
	assert_eq!(unescape("tail &amp"), "tail &amp");
	assert_eq!(unescape("&amp;amp; &#38;amp;"), "&amp; &amp;");
}

#[test]
fn unescape_decodes_references_with_leading_zeros() {
	assert_eq!(unescape("&#00000065;"), "A");
	assert_eq!(unescape("&#x00000041;"), "A");
	assert_eq!(
		unescape("&#x0000000000000000000000000000000000000041;"),
		"&#x0000000000000000000000000000000000000041;"
	);
}

/// The best of three runs, so a busy machine slows the measure less.
fn best_of_three(run: impl Fn() -> Duration) -> Duration {
	(0..3).map(|_| run()).min().expect("three runs")
}

/// Time grows by eight when the input grows by eight if the scan is
/// linear, and by sixty-four if it is quadratic. Allow three times the
/// linear growth plus a fixed slack for noise.
fn assert_linear(small: Duration, large: Duration) {
	assert!(
		large <= small * 24 + Duration::from_millis(200),
		"{small:?} for 1x, {large:?} for 8x"
	);
}

#[test]
fn unescape_work_grows_linearly_with_the_input() {
	let time = |n: usize| {
		best_of_three(|| {
			let body = format!("{};", "&".repeat(n));
			let start = Instant::now();
			assert_eq!(unescape(&body).len(), body.len());
			start.elapsed()
		})
	};
	assert_linear(time(50_000), time(400_000));
}

/// A run of `<` before a single `>` made the old scan read to the end of
/// the body for each of them.
#[test]
fn matching_close_work_grows_linearly_with_stray_angle_brackets() {
	let time = |n: usize| {
		best_of_three(|| {
			let body = format!("{}>", "<".repeat(n));
			let start = Instant::now();
			assert!(matching_close(&body, 0, "filter").is_none());
			start.elapsed()
		})
	};
	assert_linear(time(50_000), time(400_000));
}

/// A well formed body that never closes the element scans every tag once.
#[test]
fn matching_close_work_grows_linearly_with_open_elements() {
	let time = |n: usize| {
		best_of_three(|| {
			let body = "<a>".repeat(n);
			let start = Instant::now();
			assert!(matching_close(&body, 0, "filter").is_none());
			start.elapsed()
		})
	};
	assert_linear(time(50_000), time(400_000));
}

#[test]
fn matching_close_still_pairs_nested_and_self_closed_elements() {
	let body = "<a><a/><a></a></a>tail";
	let (close, next) = matching_close(body, 3, "a").expect("closes");
	assert_eq!(&body[close..next], "</a>");
	assert_eq!(&body[next..], "tail");
}

#[test]
fn matching_close_refuses_a_tag_opened_inside_a_tag() {
	assert!(matching_close("<a <b>></a>", 0, "a").is_none());
}
