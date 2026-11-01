//! The address boundary table, on its own because it is the widest of the
//! identity tables and the head file already carries two.
//!
//! Declared from `tests/contracts/validation_matrix.rs`; see that file for why a
//! module under `tests/` that is not a test target of its own is a module
//! rather than a file.

use super::common::{Row, cell, matrix, store};
use epistle::smtp::address::Address;

#[test]
fn an_address_answers_the_same_through_the_parser_and_the_store() {
	let paths = ["parse", "store"];
	// The address is 254 octets with every label inside its own cap, which is
	// the RFC 5321 ceiling the parser enforces: 63 of local part, the `@`, and
	// a domain of three labels. One more character is over it.
	let at_254 = format!(
		"{}@{}.{}.{}",
		"a".repeat(63),
		"b".repeat(63),
		"c".repeat(63),
		"d".repeat(62)
	);
	let at_255 = format!(
		"{}@{}.{}.{}",
		"a".repeat(63),
		"b".repeat(63),
		"c".repeat(63),
		"d".repeat(63)
	);
	assert_eq!(at_254.len(), 254, "the fixture sits exactly on the cap");
	assert_eq!(at_255.len(), 255, "and one octet over it");
	let mut rows = Vec::new();
	for (what, address) in [
		("empty", String::new()),
		("one character", "a".to_string()),
		("plain", "torre@example.org".to_string()),
		("upper-case local", "Torre@example.org".to_string()),
		("upper-case domain", "torre@EXAMPLE.ORG".to_string()),
		("IDN domain", "torre@b\u{fc}cher.example".to_string()),
		("punycode domain", "torre@xn--bcher-kva.example".to_string()),
		("Cyrillic look-alike", "torre@\u{435}xample.org".to_string()),
		(
			"trailing dot in the domain",
			"torre@example.org.".to_string(),
		),
		(
			"double dot in the local part",
			"torre..control@example.org".to_string(),
		),
		(
			"dot at the start of the local part",
			".torre@example.org".to_string(),
		),
		("NUL", "torre\0@example.org".to_string()),
		("CR LF", "torre\r\nBcc: x@example.org".to_string()),
		("a space", "torre control@example.org".to_string()),
		("a quote", "\"torre\"@example.org".to_string()),
		("two at signs", "torre@control@example.org".to_string()),
		("no at sign", "torre.example.org".to_string()),
		("plus tag", "torre+tag@example.org".to_string()),
		(
			"SMTPUTF8 local part",
			"torre.\u{00f1}\u{65e5}@example.org".to_string(),
		),
		(
			"SMTPUTF8 local part with a control",
			"torre\r\u{00e9}@example.org".to_string(),
		),
		(
			"SMTPUTF8 local part with a line separator",
			"torre\u{2028}control@example.org".to_string(),
		),
		(
			"SMTPUTF8 local part with a paragraph separator",
			"torre\u{2029}control@example.org".to_string(),
		),
		(
			"an internationalised address",
			"torre@b\u{fc}cher.example".to_string(),
		),
		(
			"local at 64 octets",
			format!("{}@example.org", "a".repeat(64)),
		),
		(
			"local at 65 octets",
			format!("{}@example.org", "a".repeat(65)),
		),
		("address at 254 octets", at_254),
		("address at 255 octets", at_255.clone()),
		(
			"label at 63 octets",
			format!("torre@{}.example", "a".repeat(63)),
		),
		(
			"label at 64 octets",
			format!("torre@{}.example", "a".repeat(64)),
		),
	] {
		let (_, store) = store();
		rows.push(Row {
			accepted: vec![
				Address::parse(&address).is_ok(),
				store
					.validate_for_add("torre", std::slice::from_ref(&address))
					.is_ok(),
			],
			what,
			value: address,
		});
	}
	for row in &rows {
		assert_eq!(
			row.accepted[0],
			row.accepted[1],
			"the parser and the store disagree on {:?}{}",
			row.value,
			matrix(&rows, &paths)
		);
	}
	for (what, expected) in [
		("empty", false),
		("one character", false),
		("plain", true),
		("upper-case local", true),
		("upper-case domain", true),
		("IDN domain", true),
		("punycode domain", true),
		("Cyrillic look-alike", false),
		("trailing dot in the domain", false),
		("double dot in the local part", false),
		("dot at the start of the local part", false),
		("NUL", false),
		("CR LF", false),
		("a space", false),
		("a quote", false),
		("two at signs", false),
		("no at sign", false),
		("plus tag", true),
		("SMTPUTF8 local part", true),
		("SMTPUTF8 local part with a control", false),
		("SMTPUTF8 local part with a line separator", false),
		("SMTPUTF8 local part with a paragraph separator", false),
		("an internationalised address", true),
		("local at 64 octets", true),
		("local at 65 octets", false),
		("address at 254 octets", true),
		("address at 255 octets", false),
		("label at 63 octets", true),
		("label at 64 octets", false),
	] {
		cell(&rows, &paths, what, 0, expected);
	}
	// A refusal names which rule fired, not just that one did. The local part
	// over its cap and the whole address over its cap are two different rules.
	assert!(
		epistle::util::address_reason::reason(&format!("{}@example.org", "a".repeat(65)))
			.contains("local part is 65"),
		"the overlong local part names the local part rule"
	);
	assert!(
		epistle::util::address_reason::reason(&at_255).contains("the address is 255"),
		"the overlong address names the address rule"
	);
	assert!(
		epistle::util::address_reason::reason("torre@еxample.org")
			.contains("imitates another name"),
		"a confusable domain names the confusable rule"
	);
}
