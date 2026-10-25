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

/// The domain list is compared with the same normalisation the answers
/// validator applies, so a domain it refuses cannot become the domain of
/// the first account through an insensitive comparison.
#[test]
fn an_address_in_a_domain_the_server_refuses_is_refused() {
	// The same invalid domain twice, as a list of served domains can carry.
	let served = vec!["bad..example".to_string(), "bad..example".to_string()];
	let refused = account("alice@bad..example").check(&served);
	assert!(
		refused
			.as_ref()
			.is_err_and(|why| why.contains("not a valid mail domain")),
		"{refused:?}"
	);
	// A domain the server does not serve is refused the same way it always
	// was.
	let other = account("alice@elsewhere.example").check(&served);
	assert!(
		other
			.as_ref()
			.is_err_and(|why| why.contains("not one of the configured domains")),
		"{other:?}"
	);
}

/// A role address that a dynamic account already holds is left alone: init
/// never writes an alias on top of an address that already delivers
/// somewhere.
#[test]
fn a_role_address_a_dynamic_account_holds_is_left_alone() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	std::fs::write(
		&config_path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n",
			dir.path().join("data").display()
		),
	)
	.expect("write config");
	std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let config = Config::load(&config_path).expect("config");
	std::fs::create_dir_all(&config.data_dir).expect("data dir");
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("store");
	// A dynamic account already holds the role address of the domain, spelled
	// with capitals.
	let holder = DynamicAccount::with_password(
		"postmaster".to_string(),
		vec!["Postmaster@EXAMPLE.org".to_string()],
		"Zq8!vT3#mL0@pW6$",
		&crate::password::Policy::from_config(&config.auth),
		config.auth.scram,
	)
	.expect("account");
	store.add(holder).expect("add the account");

	let mut report = Report::default();
	add_role_aliases(
		&account("alice@example.org"),
		&config,
		&config_path,
		"alice@example.org",
		&store,
		&mut report,
	)
	.expect("role aliases");

	let text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		!text.contains("postmaster@example.org"),
		"the alias was written on top of the account: {text}"
	);
	assert!(text.contains("abuse@example.org"), "{text}");
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

/// The account that already holds the name may spell its domain as a U-label
/// in a configuration the full loader rejects, and the first account may be
/// typed either way: it is still the same address, not a collision.
#[test]
fn an_existing_account_spelled_as_a_u_label_is_the_same_address() {
	let holder = vec!["Alice@B\u{fc}cher.Example".to_string()];
	for typed in ["alice@b\u{fc}cher.example", "alice@xn--bcher-kva.example"] {
		let stored = account(typed).stored_address();
		assert_eq!(name_holder("alice", &stored, &holder), Ok(true), "{typed}");
	}
	let other = vec!["alice@elsewhere.example".to_string()];
	assert!(
		name_holder("alice", "alice@xn--bcher-kva.example", &other).is_err(),
		"a different domain is still a collision"
	);
}

/// `precheck` runs with the configuration lock held, and reads the existing
/// configuration as raw TOML. A fifo there counts as no accounts instead of
/// holding the command, and the lock with it, for a writer that never comes.
#[cfg(unix)]
#[test]
fn a_fifo_where_the_configuration_belongs_is_not_waited_on() {
	use crate::cli::regular_read::{bounded, fifo_at};
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	fifo_at(&path);
	let (accounts, aliases) = bounded(&path, |path| {
		(static_accounts_of(path), static_aliases_of(path))
	});
	assert!(accounts.is_empty() && aliases.is_empty());
}
