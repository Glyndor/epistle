//! The static alias table refuses the Unicode line and paragraph separators
//! in every address it carries, as the address parser does.

use super::*;

fn alias(address: &str, members: &[&str], senders: &[&str]) -> Alias {
	Alias {
		address: address.to_string(),
		members: members.iter().map(|m| m.to_string()).collect(),
		senders: senders.iter().map(|s| s.to_string()).collect(),
		hidden: true,
		list_id: None,
	}
}

#[test]
fn a_line_or_paragraph_separator_is_refused_in_any_address_of_the_alias() {
	for separator in ['\u{2028}', '\u{2029}'] {
		let bad = format!("team{separator}ops@example.org");
		for built in [
			alias(&bad, &["alice@example.org"], &[]),
			alias("team@example.org", &[bad.as_str()], &[]),
			alias("team@example.org", &["alice@example.org"], &[bad.as_str()]),
		] {
			let error = built.validate().expect_err("a separator is refused");
			assert!(error.contains("separator"), "{error}");
		}
	}
}

#[test]
fn an_alias_without_separators_still_validates() {
	let fine = alias(
		"team@example.org",
		&["alice@example.org", "b\u{fc}ro@example.org"],
		&["alice@example.org"],
	);
	assert_eq!(fine.validate(), Ok(()));
}
