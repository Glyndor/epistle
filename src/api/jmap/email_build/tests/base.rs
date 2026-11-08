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

/// The octets a message copies out of blobs add up to one budget, so a blob
/// named many times is paid for many times.
#[test]
fn every_reference_to_a_blob_is_charged_against_the_budget_of_the_message() {
	let uploads = Uploads::default();
	let crypto = crate::storage::MessageCrypto::disabled();
	let dir = std::path::Path::new("/nonexistent");
	let sources = Sources {
		data_dir: dir,
		account: "alice",
		crypto: &crypto,
		uploads: &uploads,
		limit: 1000,
		spent: std::cell::Cell::new(0),
	};
	for _ in 0..4 {
		sources.charge(250).expect("the budget has room");
	}
	assert_eq!(
		sources.charge(1).expect_err("the budget is spent"),
		json!({"type": "tooLarge"})
	);
	// A refused part takes nothing out of the budget.
	assert_eq!(sources.spent.get(), 1000);
}
