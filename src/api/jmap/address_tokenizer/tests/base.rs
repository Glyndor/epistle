use super::find_angle_addr;
use super::reset_steps;
use super::split_top_level;

fn crafted_angle(n: usize) -> String {
	let mut s = String::with_capacity(n * 2);
	for _ in 0..n {
		s.push('<');
		s.push('a');
	}
	s
}

/// Craft an input that triggers the historical quadratic case for
/// encoded-words: 20000 `=?x` openers followed by a single trailing
/// `?=`. Every opener searches the suffix for `?=`, finds it at the
/// very end, and (in the historical algorithm) validates a payload
/// that spans almost the whole rest of the value. With N invalid
/// openers and a body of length ~3N, the historical work was
/// O(N^2) ~= 1.2 billion byte comparisons; the single-pass
/// tokenizer with a precomputed closer table walks the value once
/// and refuses anything longer than the RFC 2047 §5 cap, so each
/// opener is O(1) and the total work is O(input length).
fn crafted_invalid_encoded_words(n: usize) -> String {
	let mut s = String::with_capacity(n * 3 + 3);
	for _ in 0..n {
		s.push_str("=?x");
	}
	s.push_str(" ?=");
	s
}

#[test]
fn scan_step_count_grows_at_most_linearly_on_the_crafted_input() {
	// Existing regression: openers that never close (no `>` in a body
	// of `<a` repeated). The single-pass tokenizer touches each
	// byte at most a small constant number of times.
	let value = crafted_angle(8_192);
	reset_steps();
	let _ = split_top_level(&value, ',');
	let _ = find_angle_addr(&value);
	let steps = reset_steps();
	let len = value.len() as u64;
	assert!(
		steps > 0,
		"work counter must be > 0; a reverted algorithm that does not touch the counter bypasses the bound silently"
	);
	assert!(
		steps <= len * 8,
		"single-pass tokenizer should stay within a small constant of the header length, got {steps} for {len} bytes"
	);
}

#[test]
fn doubling_the_crafted_input_at_most_doubles_the_step_count() {
	let small = crafted_angle(4_096);
	let large = crafted_angle(8_192);
	reset_steps();
	let _ = split_top_level(&small, ',');
	let _ = find_angle_addr(&small);
	let small_steps = reset_steps();
	reset_steps();
	let _ = split_top_level(&large, ',');
	let _ = find_angle_addr(&large);
	let large_steps = reset_steps();
	assert!(
		small_steps > 0,
		"work counter must be > 0; a reverted algorithm that does not touch the counter bypasses the bound silently"
	);
	assert!(
		large_steps as u128 <= small_steps as u128 * 2 + 4096,
		"step count grew superlinearly: small={small_steps}, large={large_steps}"
	);
}

#[test]
fn unterminated_encoded_word_does_not_re_search_the_suffix() {
	// The same shape, with `=?` openers and no `?=`. The historical
	// `find_encoded_word_end` did a `payload.find("?=")` and walked
	// the components on every opener, which is the O(N * L) path
	// the issue names for encoded-words as well. The tokenizer is
	// called twice per header (once in `split_top_level`, once in
	// `find_angle_addr`), and each call builds the closer table on
	// the first opener; the bound is `5 * len` to keep a small
	// slack above the theoretical `4 * len`.
	let value = crafted_invalid_encoded_words(8_192);
	reset_steps();
	let _ = split_top_level(&value, ',');
	let _ = find_angle_addr(&value);
	let steps = reset_steps();
	let len = value.len() as u64;
	assert!(
		steps > 0,
		"work counter must be > 0; a reverted algorithm that does not touch the counter bypasses the bound silently"
	);
	assert!(
		steps <= len * 5,
		"encoded-word scan should stay within a small constant of the header length, got {steps} for {len} bytes"
	);
}

#[test]
fn invalid_openers_do_not_re_search_the_suffix() {
	// The same crafted input the reviewer named: n invalid `=?x`
	// openers, then a single `?=` at the very end. With the
	// historical per-opener suffix search this is O(n^2); the
	// precomputed closer table plus the encoded-word length cap
	// keep it O(input length). The bound is `10 * input_length`
	// because the two passes (split_top_level + find_angle_addr)
	// each build their own closer table and walk the candidate
	// walk on each opener (bounded by MAX_ENCODED_WORD_LEN per
	// opener), so the constant is higher than the single-input
	// bound above.
	let value = crafted_invalid_encoded_words(20_000);
	reset_steps();
	let _ = split_top_level(&value, ',');
	let _ = find_angle_addr(&value);
	let steps = reset_steps();
	let len = value.len() as u64;
	assert!(
		steps > 0,
		"work counter must be > 0; a reverted algorithm that does not touch the counter bypasses the bound silently"
	);
	let bound = len * 10;
	assert!(
		steps <= bound,
		"invalid opener walk must stay within a constant of the input length, got {steps} for {len} bytes (cap {bound})"
	);
	// Output: every opener is invalid (no RFC 2047 separator
	// shape inside the giant payload), so the header parses as a
	// single piece with no top-level commas. Same shape the
	// tokenizer produced before the fix; the assertion locks the
	// output so a future regression that disabled encoded-word
	// recognition entirely would also trip.
	assert_eq!(
		split_top_level(&value, ',').len(),
		1,
		"crafted input has no top-level commas"
	);
}

#[test]
fn a_valid_encoded_word_after_many_invalid_openers_is_still_recognised() {
	// Many invalid openers followed by a single RFC 2047 valid
	// encoded-word (`=?UTF-8?Q?hello?=`) and then an angle-addr.
	// The first opener search used to disable recognition for the
	// rest of the header when validation failed; the fix
	// distinguishes "invalid candidate" from "no closer exists"
	// and keeps looking, so the angle-addr at the end is still
	// found.
	let mut value = String::new();
	for _ in 0..500 {
		value.push_str("=?x");
	}
	value.push_str(" (=?UTF-8?Q?hello?=) <user@example.org>");
	let pieces = split_top_level(&value, ',');
	// The header has no top-level commas: one piece, with an
	// angle-addr at the tail.
	assert_eq!(
		pieces.len(),
		1,
		"no top-level comma: must split into one piece"
	);
	let last = pieces.last().expect("one piece");
	let angle = find_angle_addr(last);
	let (open, close) = angle.expect("angle-addr must be found");
	assert_eq!(&last[open + 1..close], "user@example.org");
}

#[test]
fn an_invalid_encoded_word_candidate_does_not_disable_later_recognition() {
	// RFC 5322 §3.2.3 permits `=?` as atom text. The first opener
	// here is followed by a space, so it cannot be a valid
	// encoded-word; the encoded-word that wraps the second
	// display name must still be recognised, so the header
	// splits to two addresses.
	let value = "=? <one@example.org>, (=?UTF-8?Q?Doe,Jane?=) <two@example.org>";
	let pieces = split_top_level(value, ',');
	assert_eq!(
		pieces.len(),
		2,
		"invalid opener must not poison the next encoded-word, got {pieces:?}"
	);
	assert!(pieces[0].contains("one@example.org"));
	assert!(pieces[1].contains("two@example.org"));
}
