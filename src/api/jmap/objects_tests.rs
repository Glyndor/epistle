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
	// names for encoded-words as well.
	let mut value = String::with_capacity(8_192 * 2);
	for _ in 0..8_192 {
		value.push_str("=?x");
	}
	reset_tokenizer_steps();
	let _ = address_list(Some(&value));
	let steps = reset_tokenizer_steps();
	let len = value.len() as u64;
	assert!(
		steps <= len * 4,
		"encoded-word scan should stay within a small constant of the header length, got {steps} for {len} bytes"
	);
}
