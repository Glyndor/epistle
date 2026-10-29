//! One test per refusal reason, asserting the exact message.

use super::*;

fn refused(raw: &str) -> String {
	parse(raw).expect_err("must be refused")
}

#[test]
fn accepts_what_the_parser_accepts() {
	let local = "a".repeat(64);
	assert!(parse(&format!("{local}@example.org")).is_ok());
	assert!(parse("Alice.Smith+tag@Example.ORG").is_ok());
}

#[test]
fn names_an_overlong_local_part() {
	let local = "a".repeat(65);
	assert_eq!(
		refused(&format!("{local}@example.org")),
		"local part is 65 characters; the maximum is 64 (RFC 5321)"
	);
}

#[test]
fn names_an_overlong_address_without_echoing_it() {
	let raw = format!("{}@example.org", "a".repeat(500));
	assert_eq!(
		refused(&raw),
		"the address is 512 characters; the maximum is 254 (RFC 5321)"
	);
}

#[test]
fn names_consecutive_leading_and_trailing_dots() {
	assert_eq!(
		refused("a..b@example.org"),
		"consecutive dots in the local part"
	);
	assert_eq!(
		refused(".a@example.org"),
		"the local part starts with a dot"
	);
	assert_eq!(refused("a.@example.org"), "the local part ends with a dot");
}

#[test]
fn names_spaces() {
	assert_eq!(refused("al ice@example.org"), "spaces are not allowed");
	assert_eq!(refused("alice@exa mple.org"), "spaces are not allowed");
}

#[test]
fn names_a_second_at_sign_and_a_missing_one() {
	assert_eq!(refused("a@b@example.org"), "only one @ is allowed");
	assert_eq!(refused("alice.example.org"), "alice.example.org has no @");
}

#[test]
fn names_quotes() {
	assert_eq!(
		refused("\"a b\"@example.org"),
		"spaces are not allowed",
		"whitespace is reported first"
	);
	assert_eq!(
		refused("\"ab\"@example.org"),
		"quoted local parts are not accepted"
	);
}

#[test]
fn names_an_empty_local_part_and_domain() {
	assert_eq!(refused("@example.org"), "the local part before @ is empty");
	assert_eq!(refused("alice@"), "the domain after @ is empty");
}

#[test]
fn names_a_disallowed_local_part_character() {
	assert_eq!(
		refused("a(b)@example.org"),
		"the character '(' is not allowed in the local part"
	);
}

#[test]
fn names_a_trailing_dot_on_the_domain() {
	assert_eq!(refused("alice@example.org."), "the domain ends with a dot");
}

#[test]
fn names_an_overlong_domain_label_and_cuts_it() {
	let label = "x".repeat(64);
	assert_eq!(
		refused(&format!("a@{label}.org")),
		format!(
			"the domain label '{}\u{2026}' is 64 characters; the maximum is 63",
			"x".repeat(40)
		)
	);
}

#[test]
fn names_an_overlong_domain() {
	let label = "y".repeat(50);
	let domain = format!("{}.org", [label.as_str(); 5].join("."));
	assert_eq!(
		domain_reason(&domain),
		"the domain is 258 characters; the maximum is 253"
	);
}

#[test]
fn names_domain_shape_problems() {
	assert_eq!(
		refused("a@localhost"),
		"the domain localhost needs at least one dot"
	);
	assert_eq!(refused("a@ex..org"), "consecutive dots in the domain");
	assert_eq!(
		refused("a@-ex.org"),
		"the domain label '-ex' starts or ends with a hyphen"
	);
	assert_eq!(
		refused("a@ex_ample.org"),
		"the character '_' is not allowed in a domain"
	);
	assert_eq!(
		refused("a@[127.0.0.1]"),
		"address literals are not accepted"
	);
}

#[test]
fn names_a_confusable_domain() {
	// Cyrillic "а" in an otherwise Latin label.
	assert_eq!(
		refused("a@ex\u{430}mple.org"),
		"the domain ex\u{430}mple.org mixes scripts or imitates another name"
	);
}

#[test]
fn names_a_domain_the_server_does_not_handle() {
	assert_eq!(
		not_handled("example.com"),
		"example.com is not a domain this server handles"
	);
}

#[test]
fn shorten_keeps_short_values_and_cuts_long_ones() {
	assert_eq!(shorten("short"), "short");
	let long = "z".repeat(41);
	assert_eq!(shorten(&long), format!("{}\u{2026}", "z".repeat(40)));
}

#[test]
fn a_refused_name_gets_the_rule_and_an_example() {
	use crate::domain::DomainError;
	assert_eq!(
		name_refusal("mail", DomainError::Invalid, "mail.example.org"),
		"the domain mail needs at least one dot; for example \"mail.example.org\""
	);
	let mixed = name_refusal("\u{435}xample.org", DomainError::Confusable, "example.org");
	assert!(mixed.contains("mixes scripts"), "{mixed}");
	assert!(mixed.ends_with("for example \"example.org\""), "{mixed}");
}

#[test]
fn a_reason_never_repeats_a_control_or_hidden_character_raw() {
	for value in [
		"mail\u{202e}.net",
		"\u{9b}2J.org",
		"x\u{2028}y",
		"a\u{9b}",
		"-\u{202e}x.example.org",
		"\u{202e}",
	] {
		for line in [
			domain_reason(value),
			name_refusal(value, crate::domain::DomainError::Invalid, "example.org"),
			name_refusal(value, crate::domain::DomainError::Confusable, "example.org"),
			not_handled(value),
		] {
			assert!(
				line.chars()
					.all(|c| !(c.is_control() || crate::util::validation::is_invisible_format(c))),
				"{value:?} came back raw in {line:?}"
			);
		}
	}
}
