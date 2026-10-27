//! The structured addresses of an `Email/set` creation refuse the Unicode line
//! and paragraph separators that the SMTP address parser refuses.

use super::*;

#[test]
fn a_line_or_paragraph_separator_in_an_address_is_an_invalid_property() {
	for property in ["from", "sender", "to", "cc", "bcc", "replyTo"] {
		for separator in ['\u{2028}', '\u{2029}'] {
			let spec = json!({ property: [{"email": format!("a{separator}b@example.org")}] });
			let error = headers(&spec).expect_err("a separator is refused");
			assert_eq!(error, invalid(&[property]), "{property} {separator:?}");
		}
	}
}

#[test]
fn an_address_without_separators_still_builds_its_header() {
	let spec = json!({
		"from": [{"email": "alice@example.org"}],
		"to": [{"name": "Bob", "email": "b\u{fc}ro@example.org"}],
	});
	let lines = headers(&spec).expect("a plain address builds");
	assert!(
		lines.iter().any(|line| line.starts_with("From:")),
		"{lines:?}"
	);
	assert!(
		lines.iter().any(|line| line.starts_with("To:")),
		"{lines:?}"
	);
}
