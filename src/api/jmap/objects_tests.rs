use super::address_list;
use super::render_address;
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

/// Integration check: the address_list pipeline (split_top_level,
/// parse_address, find_angle_addr) returns the two addresses the
/// RFC 5322 §3.2.3 atom text and the RFC 2047 encoded-word encode.
/// The tokenizer-only regressions live with the tokenizer module;
/// this is here so the full pipeline is exercised end-to-end.
#[test]
fn an_invalid_encoded_word_candidate_does_not_disable_later_recognition() {
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
