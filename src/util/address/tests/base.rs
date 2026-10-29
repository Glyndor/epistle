//! Tests for the stored form of addresses and domains.

use super::*;

#[test]
fn lowercases_ascii_local_part_and_domain() {
	assert_eq!(
		normalize("Alice.Smith@Example.ORG"),
		"alice.smith@example.org"
	);
}

#[test]
fn trims_surrounding_whitespace() {
	assert_eq!(normalize("  Team@Example.org \n"), "team@example.org");
	assert_eq!(normalize_domain(" Example.ORG "), "example.org");
}

#[test]
fn lowercases_a_non_ascii_local_part_with_unicode_rules() {
	assert_eq!(normalize("ÄRGER@example.org"), "ärger@example.org");
	assert_eq!(normalize("ΣΟΦΙΑ@example.org"), "σοφια@example.org");
}

#[test]
fn turns_an_internationalised_domain_into_its_a_label() {
	assert_eq!(
		normalize("Info@Bücher.Example"),
		"info@xn--bcher-kva.example"
	);
	assert_eq!(normalize_domain("BÜCHER.example"), "xn--bcher-kva.example");
	assert_eq!(
		normalize_domain("XN--BCHER-KVA.example"),
		"xn--bcher-kva.example"
	);
}

#[test]
fn only_the_last_at_sign_splits_the_domain() {
	assert_eq!(normalize("A@B@Example.ORG"), "a@b@example.org");
}

#[test]
fn never_validates_so_the_caller_can_say_why() {
	assert_eq!(normalize("Not An Address"), "not an address");
	assert_eq!(normalize("a@Bad_Domain.ORG"), "a@bad_domain.org");
}

#[test]
fn is_idempotent() {
	for raw in ["Alice@Example.ORG", "ÄRGER@Bücher.example", "x@Bad_Domain"] {
		let once = normalize(raw);
		assert_eq!(normalize(&once), once, "{raw}");
	}
}
