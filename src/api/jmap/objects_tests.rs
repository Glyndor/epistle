use super::address_list;
use super::render_address;
use super::reset_tokenizer_steps;
use serde_json::json;

#[test]
fn address_phrases_quote_and_escape_wire_syntax() {
	for (name, phrase) in [
		("Doe, Jane", r#""Doe, Jane""#),
		("Jane \"JJ\" Doe", r#""Jane \"JJ\" Doe""#),
		(r"Jane \ Doe", r#""Jane \\ Doe""#),
		("Jane <team>", r#""Jane <team>""#),
		("Plain Name", "Plain Name"),
	] {
		let address = json!({"name": name, "email": "jane@example.org"});
		assert_eq!(
			render_address(&address).unwrap(),
			format!("{phrase} <jane@example.org>"),
			"display name must be a valid phrase"
		);
	}
}

/// Craft the input the issue names: a large From: header with repeated
/// `<` and no matching `>`. The historical tokenizer called
/// `find_matching` for every `<`, and `find_matching` walked the rest
/// of the header to look for a `>`. With N unterminated openers and a
/// header of length L, that ran in O(N * L) = O(L^2) time.
///
/// The single-pass tokenizer visits each byte at most once. Doubling
/// the header at most roughly doubles the step counter, with a fixed
/// slack for the per-call overhead.
fn crafted_from(n: usize) -> String {
	let mut s = String::with_capacity(n * 2);
	for _ in 0..n {
		s.push('<');
		s.push('a');
	}
	s
}

#[test]
fn scan_step_count_grows_at_most_linearly_on_the_crafted_input() {
	let value = crafted_from(8_192);
	reset_tokenizer_steps();
	let _ = address_list(Some(&value));
	let steps = reset_tokenizer_steps();
	// The linear scan touches each byte at most a small constant
	// number of times. The quadratic scan touched each byte O(N)
	// times (once per opener), so it blew past the body length many
	// times over.
	let len = value.len() as u64;
	assert!(
		steps <= len * 4,
		"single-pass tokenizer should stay within a small constant of the header length, got {steps} for {len} bytes"
	);
}

#[test]
fn doubling_the_crafted_input_at_most_doubles_the_step_count() {
	let small = crafted_from(4_096);
	let large = crafted_from(8_192);
	reset_tokenizer_steps();
	let _ = address_list(Some(&small));
	let small_steps = reset_tokenizer_steps();
	reset_tokenizer_steps();
	let _ = address_list(Some(&large));
	let large_steps = reset_tokenizer_steps();
	// linear: count(2N) <= 2 * count(N) + slack
	assert!(
		large_steps as u128 <= small_steps as u128 * 2 + 4096,
		"step count grew superlinearly: small={small_steps}, large={large_steps}"
	);
}

#[test]
fn unterminated_encoded_word_does_not_re_search_the_suffix() {
	// The same shape, with `=?` openers and no `?=`. The historical
	// `find_encoded_word_end` did a `payload.find("?=")` and walked the
	// components on every opener, which is the O(N * L) path the issue
	// names for encoded-words as well. The tokenizer is called twice
	// per header (once in `split_top_level`, once in `find_angle_addr`),
	// and each call counts the suffix search, so the bound is
	// `5 * len` to keep a small slack above the theoretical `4 * len`.
	let mut value = String::with_capacity(8_192 * 2);
	for _ in 0..8_192 {
		value.push_str("=?x");
	}
	reset_tokenizer_steps();
	let _ = address_list(Some(&value));
	let steps = reset_tokenizer_steps();
	let len = value.len() as u64;
	assert!(
		steps <= len * 5,
		"encoded-word scan should stay within a small constant of the header length, got {steps} for {len} bytes"
	);
}

#[test]
fn an_invalid_encoded_word_candidate_does_not_disable_later_recognition() {
	// The leading `=?` is permitted atom text (RFC 5322 §3.2.3) and is
	// followed by a space, so it is not a valid encoded-word opener.
	// The historical tokenizer treated the validation failure as
	// "no closer exists" and disabled encoded-word recognition for the
	// rest of the header, which split the second address on the comma
	// inside the Q-encoded display name. The fix distinguishes
	// "invalid candidate" from "no closer exists": the first `=?` is
	// left as text and the Q-encoded comma stays inside the
	// encoded-word, so the header parses to the two addresses the
	// writer wrote.
	let value = "=? <one@example.org>, (=?UTF-8?Q?Doe,Jane?=) <two@example.org>";
	let parsed = address_list(Some(value));
	let arr = parsed.as_array().expect("address list");
	assert_eq!(
		arr.len(),
		2,
		"invalid opener must not poison later encoded-word recognition, got {arr:?}"
	);
	assert_eq!(arr[0]["email"], "one@example.org");
	assert_eq!(arr[1]["email"], "two@example.org");
}
