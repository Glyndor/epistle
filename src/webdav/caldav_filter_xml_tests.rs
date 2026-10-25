use super::*;
use std::time::Instant;

#[test]
fn unescape_decodes_entities_and_keeps_the_rest() {
	assert_eq!(unescape("a &amp; b &lt;c&gt; &#65;&#x42;"), "a & b <c> AB");
	assert_eq!(unescape("a & b"), "a & b");
	assert_eq!(unescape("x &unknown; y"), "x &unknown; y");
	assert_eq!(unescape("tail &amp"), "tail &amp");
}

/// A run of `&` with a single `;` at the end must be decoded in time that
/// grows in step with its length, not with its square.
#[test]
fn unescape_work_grows_linearly_with_the_input() {
	let time = |n: usize| {
		let body = format!("{};", "&".repeat(n));
		let start = Instant::now();
		let out = unescape(&body);
		assert_eq!(out.len(), body.len());
		start.elapsed()
	};
	let small = time(50_000);
	let large = time(400_000);
	// Eight times the input; a quadratic scan would take sixty-four times.
	assert!(
		large < small * 8 * 4 + std::time::Duration::from_millis(50),
		"{small:?} for 50k, {large:?} for 400k"
	);
}

#[test]
fn matching_close_work_grows_linearly_with_unclosed_tags() {
	let time = |n: usize| {
		let body = format!("{}>", "<".repeat(n));
		let start = Instant::now();
		assert!(matching_close(&body, 0, "filter").is_none());
		start.elapsed()
	};
	let small = time(50_000);
	let large = time(400_000);
	assert!(
		large < small * 8 * 4 + std::time::Duration::from_millis(50),
		"{small:?} for 50k, {large:?} for 400k"
	);
}

#[test]
fn matching_close_still_pairs_nested_and_self_closed_elements() {
	let body = "<a><a/><a></a></a>tail";
	let (close, next) = matching_close(body, 3, "a").expect("closes");
	assert_eq!(&body[close..next], "</a>");
	assert_eq!(&body[next..], "tail");
}
