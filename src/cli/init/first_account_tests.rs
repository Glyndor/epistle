//! The first account's rules: where its address may live, the name it
//! gets, and which role addresses point at it.

use super::*;

fn domains() -> Vec<String> {
	vec!["example.org".to_string(), "example.net".to_string()]
}

fn account(address: &str) -> FirstAccount {
	FirstAccount {
		address: address.to_string(),
		display_name: None,
		password_file: None,
		role_aliases: true,
	}
}

#[test]
fn an_address_in_a_configured_domain_names_the_account_by_its_local_part() {
	let first = account("Alice@Example.org");
	assert_eq!(first.check(&domains()), Ok(()));
	assert_eq!(first.name(), "alice");
	assert_eq!(first.stored_address(), "alice@example.org");
}

#[test]
fn an_address_outside_the_domains_or_with_an_unusable_local_part_is_refused() {
	let outside = account("alice@elsewhere.example").check(&domains());
	assert!(
		outside
			.as_ref()
			.is_err_and(|why| why.contains("not one of the configured domains")),
		"{outside:?}"
	);
	let dotted = account("jose.perez@example.org").check(&domains());
	assert!(
		dotted
			.as_ref()
			.is_err_and(|why| why.contains("lowercase letters, digits and hyphens")),
		"{dotted:?}"
	);
	assert!(account("not-an-address").check(&domains()).is_err());
	let mut named = account("alice@example.org");
	named.display_name = Some("bad\u{7}name".to_string());
	assert!(named.check(&domains()).is_err());
}

#[test]
fn postmaster_and_abuse_of_every_domain_point_at_the_account_but_never_at_itself() {
	assert_eq!(
		account("alice@example.org").role_addresses(&domains()),
		[
			"postmaster@example.org",
			"abuse@example.org",
			"postmaster@example.net",
			"abuse@example.net",
		]
	);
	assert_eq!(
		account("postmaster@example.org").role_addresses(&domains()),
		[
			"abuse@example.org",
			"postmaster@example.net",
			"abuse@example.net"
		]
	);
	let mut off = account("alice@example.org");
	off.role_aliases = false;
	assert!(off.role_addresses(&domains()).is_empty());
}

#[test]
fn the_password_is_never_printed_by_debug() {
	let password = Password::new("Zq8!vT3#mL0@pW6$".to_string());
	assert_eq!(format!("{password:?}"), "Password(<redacted>)");
	assert_eq!(password.expose(), "Zq8!vT3#mL0@pW6$");
}

#[test]
fn an_inline_password_in_the_answers_file_is_refused() {
	let parsed: Result<FirstAccount, _> =
		toml::from_str("address = \"alice@example.org\"\npassword = \"Zq8!vT3#mL0@pW6$\"\n");
	assert!(parsed.is_err(), "an inline password must not deserialise");
}
