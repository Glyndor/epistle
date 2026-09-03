//! Tests for the SMTP address parser.

use super::*;

#[test]
fn parses_internationalized_address() {
	// SMTPUTF8 (RFC 6531): UTF-8 in the local part and domain labels.
	let address = Address::parse("用户@例え.example").expect("valid utf-8 address");
	assert_eq!(address.local_part(), "用户");
	assert_eq!(address.domain(), "例え.example");
	// Control characters are still rejected.
	assert!(Address::parse("a\u{7f}b@example.org").is_err());
}

#[test]
fn parses_simple_address() {
	let address = Address::parse("alice@example.org").expect("valid");
	assert_eq!(address.local_part(), "alice");
	assert_eq!(address.domain(), "example.org");
	assert_eq!(address.to_string(), "alice@example.org");
}

#[test]
fn lowercases_domain_but_preserves_local_part() {
	let address = Address::parse("Alice.B@EXAMPLE.ORG").expect("valid");
	assert_eq!(address.local_part(), "Alice.B");
	assert_eq!(address.domain(), "example.org");
}

#[test]
fn accepts_subaddressing_and_special_atoms() {
	assert!(Address::parse("user+tag@example.org").is_ok());
	assert!(Address::parse("user_name@example.org").is_ok());
	assert!(Address::parse("user=x{a}!b@example.org").is_ok());
}

#[test]
fn rejects_missing_at_sign() {
	assert_eq!(
		Address::parse("example.org"),
		Err(AddressError::MissingAtSign)
	);
}

#[test]
fn rejects_empty_or_dotted_local_part() {
	assert_eq!(
		Address::parse("@example.org"),
		Err(AddressError::InvalidLocalPart)
	);
	assert_eq!(
		Address::parse(".a@example.org"),
		Err(AddressError::InvalidLocalPart)
	);
	assert_eq!(
		Address::parse("a..b@example.org"),
		Err(AddressError::InvalidLocalPart)
	);
}

#[test]
fn rejects_quoted_local_part() {
	assert_eq!(
		Address::parse("\"a b\"@example.org"),
		Err(AddressError::InvalidLocalPart)
	);
}

#[test]
fn rejects_overlong_local_part() {
	let raw = format!("{}@example.org", "a".repeat(MAX_LOCAL_PART + 1));
	assert_eq!(Address::parse(&raw), Err(AddressError::InvalidLocalPart));
}

#[test]
fn rejects_overlong_address() {
	let raw = format!("a@{}.example.org", "b".repeat(MAX_ADDRESS));
	assert_eq!(Address::parse(&raw), Err(AddressError::TooLong));
}

#[test]
fn rejects_bad_domains() {
	assert_eq!(Address::parse("a@"), Err(AddressError::InvalidDomain));
	assert_eq!(Address::parse("a@nodot"), Err(AddressError::InvalidDomain));
	assert_eq!(
		Address::parse("a@-bad.example.org"),
		Err(AddressError::InvalidDomain)
	);
	assert_eq!(
		Address::parse("a@bad-.example.org"),
		Err(AddressError::InvalidDomain)
	);
	assert_eq!(
		Address::parse("a@exa_mple.org"),
		Err(AddressError::InvalidDomain)
	);
	assert_eq!(
		Address::parse("a@[127.0.0.1]"),
		Err(AddressError::InvalidDomain)
	);
}

#[test]
fn rejects_overlong_domain_label() {
	let raw = format!("a@{}.org", "b".repeat(64));
	assert_eq!(Address::parse(&raw), Err(AddressError::InvalidDomain));
}
