//! Tests for the `epistle account …` umbrella command.
//!
//! Every test opens an `AccountStore` against a temp data_dir with the
//! same fixtures the rest of the suite uses (one static account
//! `alice`, one dynamic `bob` minted through the add helper) so the
//! handlers can drive the mutators end-to-end. The harness wraps the
//! store in a minimal `Config` so the CLI functions take the same code
//! the production CLI does, without spinning up a real epistle server.
//!
//! The public-view tests assert against the exact output text the CLI
//! prints: "name:", "source: dynamic", etc. so a future cosmetic
//! change is caught here as an explicit review, not silently.

use std::io::Cursor;
use std::sync::Arc;

use super::*;
use crate::config::Account;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::{fixture_password, hash};

pub(super) const STATIC_NAME: &str = "alice";
pub(super) const DYNAMIC_NAME: &str = "bob";
const DOMAIN: &str = "example.org";

pub(super) struct Harness {
	#[allow(dead_code)]
	dir: tempfile::TempDir,
	config: tempfile::NamedTempFile,
	#[allow(dead_code)]
	store: Arc<AccountStore>,
}

fn write_config(toml: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	std::io::Write::write_all(&mut file, toml.as_bytes()).expect("write");
	file
}

pub(super) fn build() -> Harness {
	let dir = tempfile::tempdir().expect("tempdir");
	let static_account = Account {
		display_name: None,
		name: STATIC_NAME.to_string(),
		addresses: vec![format!("{STATIC_NAME}@{DOMAIN}")],
		password_hash: Some(hash(fixture_password())),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = AccountStore::open(
		dir.path(),
		vec![DOMAIN.to_string()],
		std::collections::HashMap::new(),
		vec![static_account],
	)
	.expect("open store");
	let dynamic = DynamicAccount {
		name: DYNAMIC_NAME.to_string(),
		addresses: vec![format!("{DYNAMIC_NAME}@{DOMAIN}")],
		password_hash: hash(fixture_password()),
		scram: None,
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
		..DynamicAccount::default()
	};
	store.add(dynamic).expect("add dynamic");
	let config = write_config(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{DOMAIN}\"]\n\n\
		 [[accounts]]\nname = \"{STATIC_NAME}\"\naddresses = [\"{STATIC_NAME}@{DOMAIN}\"]\n",
		dir.path()
	));
	Harness {
		dir,
		config,
		store: Arc::new(store),
	}
}

/// Open the harness store directly so tests can read it back without
/// going through the CLI.
pub(super) fn reload_store(harness: &Harness) -> AccountStore {
	let config = crate::config::Config::load(harness.config.path()).expect("load config");
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("reopen store")
}

#[test]
fn password_change_makes_old_password_fail_and_new_one_authenticate() {
	let harness = build();
	let mut store = reload_store(&harness);

	// Change the password to a fresh one generated for this run.
	let new_password = crate::test_fixtures::second_password();
	assert_eq!(
		account::password_with_store(
			&store,
			DYNAMIC_NAME,
			Cursor::new(format!("{new_password}\n")),
		),
		ExitCode::SUCCESS,
		"password change should succeed"
	);
	store = reload_store(&harness);

	// The new password authenticates through the rebuilt directory.
	let directory = store.handle().current();
	let protocol = crate::config::Protocol::Api;
	assert_eq!(
		directory
			.authenticate(DYNAMIC_NAME, new_password, protocol)
			.as_deref(),
		Some(DYNAMIC_NAME),
		"the new password must authenticate"
	);
	// The old password no longer does. We use the fixture as the "old"
	// here, the test built bob with hash(fixture_password()), so the
	// fixture was the original password.
	assert!(
		directory
			.authenticate(DYNAMIC_NAME, fixture_password(), protocol)
			.is_none(),
		"the original password must no longer authenticate"
	);
}

#[test]
fn password_change_also_updates_scram_credentials() {
	use crate::smtp::scram::ScramCredentials;

	let harness = build();
	let store = reload_store(&harness);

	// Change the password and read the SCRAM credentials back off the
	// dynamic row. The new password's stored_key under the salt on
	// disk must match a fresh SCRAM derivation, which is the whole
	// point of keeping scram in sync with the password hash.
	let new_password = crate::test_fixtures::wrong_password();
	assert_eq!(
		account::password_with_store(
			&store,
			DYNAMIC_NAME,
			Cursor::new(format!("{new_password}\n")),
		),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let stored = store
		.dynamic(DYNAMIC_NAME)
		.expect("dynamic account still present after password change")
		.scram
		.expect("a password change must set fresh SCRAM credentials");
	let credentials = stored.to_credentials().expect("parse stored SCRAM");
	let fresh = ScramCredentials::derive(new_password, &credentials.salt, credentials.iterations);
	assert_eq!(
		fresh.stored_key.as_slice(),
		credentials.stored_key.as_slice(),
		"SCRAM stored_key must match a fresh derivation under the new password"
	);
}

#[test]
fn disable_makes_authentication_fail() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::disable_with_store(&store, DYNAMIC_NAME),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let directory = store.handle().current();
	assert!(
		directory
			.authenticate(
				DYNAMIC_NAME,
				fixture_password(),
				crate::config::Protocol::Api
			)
			.is_none(),
		"a disabled account must reject authentication identically to an unknown login"
	);
}

#[test]
fn enable_lifts_the_disabled_flag() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::disable_with_store(&store, DYNAMIC_NAME),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	assert_eq!(
		account::enable_with_store(&store, DYNAMIC_NAME),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate(
				DYNAMIC_NAME,
				fixture_password(),
				crate::config::Protocol::Api
			)
			.as_deref(),
		Some(DYNAMIC_NAME),
		"re-enabling a disabled account must restore it"
	);
}

#[test]
fn parse_quota_size_accepts_known_units_and_none() {
	assert_eq!(
		account::parse_quota_size("500M").expect("500M"),
		Some(500 * 1024 * 1024)
	);
	assert_eq!(
		account::parse_quota_size("10G").expect("10G"),
		Some(10 * 1024 * 1024 * 1024)
	);
	assert_eq!(
		account::parse_quota_size("1T").expect("1T"),
		Some(1024_u64.pow(4))
	);
	assert_eq!(account::parse_quota_size("none").expect("none"), None);
	assert_eq!(account::parse_quota_size("None").expect("None"), None);
	// Lower-case suffix is also accepted so operators do not have to
	// remember which letter is upper-case in which shell.
	assert_eq!(
		account::parse_quota_size("500m").expect("500m"),
		Some(500 * 1024 * 1024)
	);
}

#[test]
fn parse_quota_size_rejects_typos() {
	for bad in ["", "abc", "500X", "5M0", "M", "500", "-1G"] {
		assert!(
			account::parse_quota_size(bad).is_err(),
			"expected error for {bad:?}"
		);
	}
}

#[test]
fn quota_setter_rebuilds_the_directory() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::quota_with_store(&store, DYNAMIC_NAME, Some(500 * 1024 * 1024)),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let directory = store.handle().current();
	assert_eq!(directory.quota_for(DYNAMIC_NAME), Some(500 * 1024 * 1024));
}

#[test]
fn quota_setter_none_clears_the_quota() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::quota_with_store(&store, DYNAMIC_NAME, Some(1024)),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	assert_eq!(
		account::quota_with_store(&store, DYNAMIC_NAME, None),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	assert_eq!(store.handle().current().quota_for(DYNAMIC_NAME), None);
}

#[test]
fn parse_protocol_list_accepts_known_lists_and_all() {
	use crate::config::Protocol;
	assert_eq!(
		account::parse_protocol_list("imap,smtp").expect("imap,smtp"),
		Some(vec![Protocol::Imap, Protocol::Smtp])
	);
	assert_eq!(account::parse_protocol_list("all").expect("all"), None);
	assert_eq!(account::parse_protocol_list("ALL").expect("ALL"), None);
	assert_eq!(
		account::parse_protocol_list("api").expect("api"),
		Some(vec![Protocol::Api])
	);
}

#[test]
fn parse_protocol_list_rejects_unknown_protocols() {
	assert!(account::parse_protocol_list("imap,bogus").is_err());
	assert!(account::parse_protocol_list("").is_err());
}

#[test]
fn protocols_setter_restricts_authentication() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::protocols_with_store(
			&store,
			DYNAMIC_NAME,
			Some(vec![crate::config::Protocol::Api])
		),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate(
				DYNAMIC_NAME,
				fixture_password(),
				crate::config::Protocol::Api
			)
			.as_deref(),
		Some(DYNAMIC_NAME),
		"the listed protocol still authenticates"
	);
	assert!(
		directory
			.authenticate(
				DYNAMIC_NAME,
				fixture_password(),
				crate::config::Protocol::Imaps
			)
			.is_none(),
		"the unlisted protocol rejects"
	);
}

#[test]
fn address_add_resolves_after_reload() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::address_add_with_store(&store, DYNAMIC_NAME, &format!("{DYNAMIC_NAME}2@{DOMAIN}")),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let directory = store.handle().current();
	assert_eq!(
		directory.resolve(
			&crate::smtp::address::Address::parse(&format!("{DYNAMIC_NAME}2@{DOMAIN}")).expect("a")
		),
		crate::smtp::directory::Resolution::Account(DYNAMIC_NAME.to_string())
	);
}

#[test]
fn address_add_rejects_static_address() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::address_add_with_store(&store, DYNAMIC_NAME, &format!("{STATIC_NAME}@{DOMAIN}")),
		ExitCode::from(2),
		"address owned by a static account must be refused"
	);
}

#[test]
fn address_add_rejects_foreign_domain() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::address_add_with_store(
			&store,
			DYNAMIC_NAME,
			&format!("{DYNAMIC_NAME}@elsewhere.example")
		),
		ExitCode::from(2)
	);
}

#[test]
fn address_remove_unresolves_after_reload() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::address_add_with_store(&store, DYNAMIC_NAME, &format!("{DYNAMIC_NAME}2@{DOMAIN}")),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	assert_eq!(
		account::address_remove_with_store(
			&store,
			DYNAMIC_NAME,
			&format!("{DYNAMIC_NAME}2@{DOMAIN}")
		),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	let directory = store.handle().current();
	assert_eq!(
		directory.resolve(
			&crate::smtp::address::Address::parse(&format!("{DYNAMIC_NAME}2@{DOMAIN}")).expect("a")
		),
		crate::smtp::directory::Resolution::UnknownUser
	);
}

#[test]
fn static_account_refused_with_edit_config_hint() {
	let harness = build();
	let store = reload_store(&harness);
	// Every mutator refuses a static account with the same hint.
	for code in [
		account::password_with_store(&store, STATIC_NAME, Cursor::new("a-long-password\n")),
		account::disable_with_store(&store, STATIC_NAME),
		account::enable_with_store(&store, STATIC_NAME),
		account::address_add_with_store(&store, STATIC_NAME, &format!("new@{DOMAIN}")),
		account::address_remove_with_store(&store, STATIC_NAME, &format!("{STATIC_NAME}@{DOMAIN}")),
		account::quota_with_store(&store, STATIC_NAME, Some(1024)),
		account::protocols_with_store(&store, STATIC_NAME, None),
	] {
		assert_eq!(code, ExitCode::from(2), "static account must be refused");
	}
}

#[test]
fn show_prints_public_view_without_secrets() {
	let harness = build();
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, DYNAMIC_NAME, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("name: bob"), "{text}");
	assert!(text.contains("source: dynamic"), "{text}");
	assert!(text.contains("addresses: bob@example.org"), "{text}");
	assert!(text.contains("disabled: no"), "{text}");
	assert!(text.contains("quota_bytes: server default"), "{text}");
	assert!(text.contains("protocols: all"), "{text}");
	// The public view must never carry the password hash, the SCRAM
	// credentials, or the TOTP secret.
	assert!(!text.contains("argon2id"), "{text}");
	assert!(!text.contains("scram"), "{text}");
	assert!(!text.contains("totp"), "{text}");
	assert!(!text.contains("password_hash"), "{text}");
}

#[test]
fn show_prints_static_view_without_secrets() {
	let harness = build();
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, STATIC_NAME, &mut out),
		ExitCode::SUCCESS,
		"static accounts are addressable through `account show` (read-only)"
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("name: alice"), "{text}");
	assert!(text.contains("source: static"), "{text}");
	assert!(text.contains("addresses: alice@example.org"), "{text}");
	assert!(text.contains("quota_bytes: server default"), "{text}");
	assert!(text.contains("protocols: all"), "{text}");
	// The static view must never carry the password hash.
	assert!(!text.contains("argon2id"), "{text}");
	assert!(!text.contains("password_hash"), "{text}");
}

#[test]
fn show_refuses_unknown_account() {
	let harness = build();
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, "nobody", &mut out),
		ExitCode::from(2),
		"a name that exists nowhere must say so",
	);
}

#[test]
fn show_handles_set_quota_and_protocols() {
	let harness = build();
	let store = reload_store(&harness);
	account::quota_with_store(&store, DYNAMIC_NAME, Some(500 * 1024 * 1024));
	account::protocols_with_store(
		&store,
		DYNAMIC_NAME,
		Some(vec![crate::config::Protocol::Api]),
	);
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, DYNAMIC_NAME, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("quota_bytes: 524288000"), "{text}");
	assert!(text.contains("protocols: api"), "{text}");
}

#[test]
fn parse_quota_size_parser_accepts_whitespace_units() {
	// Trailing whitespace after the unit is allowed: a copy-paste from
	// a config file may include a stray space, and rejecting it serves
	// no one.
	assert_eq!(
		account::parse_quota_size("500M ").expect("trailing space"),
		Some(500 * 1024 * 1024)
	);
}
