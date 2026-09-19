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
