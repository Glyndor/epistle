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
	assert!(account("not-an-address").check(&domains()).is_err());
	let mut named = account("alice@example.org");
	named.display_name = Some("bad\u{7}name".to_string());
	assert!(named.check(&domains()).is_err());
}

#[test]
fn a_dot_in_the_address_gives_a_hyphenated_account_name() {
	let first = account("Torre.Control@example.org");
	assert_eq!(first.check(&domains()), Ok(()));
	assert_eq!(first.name(), "torre-control");
	assert_eq!(first.stored_address(), "torre.control@example.org");
	assert_eq!(
		first.name_note().as_deref(),
		Some(
			"the account name will be \"torre-control\" (dots become hyphens and capital letters become lowercase)"
		)
	);
	assert_eq!(
		account("torre.control@example.org").name_note().as_deref(),
		Some("the account name will be \"torre-control\" (dots become hyphens)")
	);
	assert_eq!(
		account("Alice@example.org").name_note().as_deref(),
		Some("the account name will be \"alice\" (capital letters become lowercase)")
	);
	assert_eq!(account("alice@example.org").name_note(), None);
}

#[test]
fn an_address_whose_local_part_cannot_give_a_name_is_refused_naming_the_character() {
	for (address, expected) in [
		(".torre@example.org", "starts with a dot"),
		("torre.@example.org", "ends with a dot"),
		("torre..control@example.org", "two dots in a row"),
		("jose_perez@example.org", "'_'"),
		("josé@example.org", "'é'"),
		("-torre@example.org", "hyphen"),
	] {
		let refused = account(address).check(&domains());
		assert!(
			refused.as_ref().is_err_and(|why| why.contains(expected)),
			"{address}: {refused:?}"
		);
	}
	let refused = account("jose_perez@example.org").check(&domains());
	assert!(
		refused
			.as_ref()
			.is_err_and(|why| why.contains("ASCII capital letters are converted")),
		"init says it converts capitals: {refused:?}"
	);
	let long = format!("{}@example.org", "a".repeat(65));
	assert!(account(&long).check(&domains()).is_err());
}

#[test]
fn an_existing_account_with_the_same_name_but_other_addresses_is_a_collision() {
	let same = vec!["torre.control@example.org".to_string()];
	assert_eq!(
		name_holder("torre-control", "torre.control@example.org", &same),
		Ok(true)
	);
	let other = vec!["torre-control@example.org".to_string()];
	let why = name_holder("torre-control", "torre.control@example.org", &other)
		.expect_err("a different address under the same name must not be skipped");
	assert!(
		why.contains("torre-control@example.org") && why.contains("same name"),
		"{why}"
	);
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

/// The typed domain of the first account is compared in the form the system
/// stores, so a U-label and an A-label of the same domain are one domain.
#[test]
fn an_internationalised_domain_matches_whichever_form_is_typed_or_configured() {
	let a_label = vec!["xn--bcher-kva.example".to_string()];
	let u_label = vec!["b\u{fc}cher.example".to_string()];
	for typed in ["alice@b\u{fc}cher.example", "alice@xn--bcher-kva.example"] {
		for configured in [&a_label, &u_label] {
			let first = account(typed);
			assert_eq!(
				first.check(configured),
				Ok(()),
				"{typed} against {configured:?}"
			);
			assert_eq!(first.stored_address(), "alice@xn--bcher-kva.example");
		}
	}
	let other = account("alice@b\u{fc}cher.example").check(&domains());
	assert!(
		other
			.as_ref()
			.is_err_and(|why| why.contains("not one of the configured domains")),
		"{other:?}"
	);
}
