//! Tests for the mutators that the `epistle account` subcommand drives:
//! `set_quota_bytes`, `set_allowed_protocols`, `add_address`,
//! `remove_address`, `is_static`, and the static-account refusal path.
//!
//! Every mutator is invoked on a fresh `AccountStore` opened against a
//! tempdir so the file-watcher reload path stays irrelevant to what the
//! tests assert. The fixture accounts use real argon2id hashes so the
//! password path actually runs through `Directory::authenticate`.

use std::path::Path;

use super::*;
use crate::smtp::address::Address;
use crate::smtp::auth::tests::fixture_password;
use crate::smtp::directory::Resolution;

fn static_account() -> Account {
	Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some(crate::smtp::auth::tests::hash(fixture_password())),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

fn open_store(dir: &Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![static_account()],
	)
	.expect("open store")
}

fn add_bob(store: &AccountStore) {
	let account = DynamicAccount {
		name: "bob".to_string(),
		addresses: vec!["bob@example.org".to_string()],
		password_hash: crate::smtp::auth::tests::hash(fixture_password()),
		scram: None,
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
	};
	store.add(account).expect("add bob");
}

/// `set_quota_bytes` must replace the quota the rebuilt directory
/// reports for the account, the same path IMAP `GETQUOTAROOT` and the
/// delivery quota check actually consult.
#[test]
fn set_quota_bytes_rebuilds_directory_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	store
		.set_quota_bytes("bob", Some(500 * 1024 * 1024))
		.expect("set quota");

	let directory = store.handle().current();
	assert_eq!(directory.quota_for("bob"), Some(500 * 1024 * 1024));
}

/// Setting the quota to `None` falls back to the server default (no
/// per-account and no per-domain quota configured here), exactly the way
/// the static account's `quota_bytes = None` does.
#[test]
fn set_quota_bytes_none_clears_the_dynamic_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);
	store
		.set_quota_bytes("bob", Some(1234))
		.expect("set quota first");
	store.set_quota_bytes("bob", None).expect("clear quota");

	assert_eq!(store.handle().current().quota_for("bob"), None);
}

/// `set_quota_bytes` on an unknown dynamic account surfaces the same
/// `NotFound` the rest of the dynamic mutators already use, so a typo
/// in the CLI is reported identically.
#[test]
fn set_quota_bytes_rejects_unknown_dynamic_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	assert!(matches!(
		store.set_quota_bytes("ghost", Some(1024)),
		Err(StoreError::NotFound(_))
	));
}

/// Static accounts are not addressable through the dynamic mutators:
/// editing them means editing the config file. The mutator must refuse
/// so the CLI's "edit the config" hint can be surfaced.
#[test]
fn set_quota_bytes_rejects_static_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	assert!(matches!(
		store.set_quota_bytes("alice", Some(1024)),
		Err(StoreError::NotFound(_))
	));
}

/// The mutator returns the previous quota so the CLI can report "0 ->
/// 500M" without re-reading the file. Stored alongside the assertion so a
/// later change that drops the return value is caught here.
#[test]
fn set_quota_bytes_returns_previous_value() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert_eq!(
		store.set_quota_bytes("bob", Some(2048)).expect("set"),
		None,
		"first set returns the prior None"
	);
	assert_eq!(
		store.set_quota_bytes("bob", Some(4096)).expect("set"),
		Some(2048),
		"second set returns the prior value"
	);
}

/// `set_allowed_protocols` rebuilds the directory so the gate in
/// `authenticate_with_ip` reflects the new restriction on the very next
/// authentication attempt, not after a reload.
#[test]
fn set_allowed_protocols_propagates_to_directory() {
	use crate::config::Protocol;
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	store
		.set_allowed_protocols("bob", Some(vec![Protocol::Api]))
		.expect("set protocols");

	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate("bob", fixture_password(), Protocol::Api)
			.as_deref(),
		Some("bob"),
		"the listed protocol still authenticates"
	);
	assert!(
		directory
			.authenticate("bob", fixture_password(), Protocol::Imaps)
			.is_none(),
		"the unlisted protocol rejects identically to an unknown login"
	);
}

/// Setting the allowlist back to `None` lifts the restriction; the
/// pre-restriction behaviour (every protocol authenticates) returns.
#[test]
fn set_allowed_protocols_none_clears_the_restriction() {
	use crate::config::Protocol;
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);
	store
		.set_allowed_protocols("bob", Some(vec![Protocol::Api]))
		.expect("restrict");

	store.set_allowed_protocols("bob", None).expect("clear");

	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate("bob", fixture_password(), Protocol::Imaps)
			.as_deref(),
		Some("bob"),
		"clearing the allowlist restores the unrestricted behaviour"
	);
}

/// `add_address` must refuse an address already owned by a static
/// account; the collision is the same check `add` runs on a fresh
/// dynamic account. Static config wins on a name conflict and on an
/// address conflict.
#[test]
fn add_address_rejects_static_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert!(matches!(
		store.add_address("bob", "alice@example.org"),
		Err(StoreError::Duplicate(_))
	));
}

/// `add_address` must refuse an address outside the configured domains,
/// the same check `add` runs.
#[test]
fn add_address_rejects_foreign_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert!(matches!(
		store.add_address("bob", "bob@elsewhere.example"),
		Err(StoreError::Invalid(_))
	));
}

/// `add_address` must refuse a malformed address. The validation
/// happens here so a CLI typo never reaches the on-disk file.
#[test]
fn add_address_rejects_malformed_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert!(matches!(
		store.add_address("bob", "not an email"),
		Err(StoreError::Invalid(_))
	));
}

/// `add_address` persists and rebuilds the directory so the new
/// address resolves on the next delivery attempt.
#[test]
fn add_address_persists_and_resolves() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	store
		.add_address("bob", "bob2@example.org")
		.expect("add second address");

	let handle = store.handle();
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("bob2@example.org").expect("a")),
		Resolution::Account("bob".to_string())
	);

	// Reload round-trip: a fresh store reads the new address too, so
	// the file watcher would have picked it up.
	let reopened = open_store(dir.path());
	assert_eq!(
		reopened
			.handle()
			.current()
			.resolve(&Address::parse("bob2@example.org").expect("a")),
		Resolution::Account("bob".to_string())
	);
}

/// `add_address` on an unknown account is `NotFound`; static accounts
/// are also unreachable through this mutator.
#[test]
fn add_address_rejects_unknown_or_static_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	assert!(matches!(
		store.add_address("alice", "new@example.org"),
		Err(StoreError::NotFound(_))
	));
	assert!(matches!(
		store.add_address("ghost", "new@example.org"),
		Err(StoreError::NotFound(_))
	));
}

/// `remove_address` refuses to drop the last address; the directory
/// requires at least one delivery target per account. The error is the
/// same `Invalid` shape the rest of the mutators already use.
#[test]
fn remove_address_refuses_to_drop_last_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert!(matches!(
		store.remove_address("bob", "bob@example.org"),
		Err(StoreError::Invalid(_))
	));
}

/// `remove_address` on a non-member address is `Invalid` (not
/// `NotFound`): the account exists, the address simply is not theirs.
#[test]
fn remove_address_rejects_non_member_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert!(matches!(
		store.remove_address("bob", "bob2@example.org"),
		Err(StoreError::Invalid(_))
	));
}

/// `remove_address` rebuilds the directory and persists so the address
/// stops resolving on the next delivery attempt and survives a reopen.
#[test]
fn remove_address_persists_and_unresolves() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);
	store
		.add_address("bob", "bob2@example.org")
		.expect("add second address");

	store
		.remove_address("bob", "bob2@example.org")
		.expect("remove second address");

	let handle = store.handle();
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("bob2@example.org").expect("a")),
		Resolution::UnknownUser
	);
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("bob@example.org").expect("a")),
		Resolution::Account("bob".to_string()),
		"the surviving address still resolves"
	);

	let reopened = open_store(dir.path());
	assert_eq!(
		reopened
			.handle()
			.current()
			.resolve(&Address::parse("bob2@example.org").expect("a")),
		Resolution::UnknownUser,
		"the removal survives a reopen"
	);
}

/// `is_static` is the cheap pre-check the CLI uses to reject "edit the
/// config" hints without having to attempt the mutation. Dynamic-only
/// names return false; static names return true; unknown names return
/// false (the unknown case is the mutator's `NotFound` to report).
#[test]
fn is_static_distinguishes_static_and_dynamic() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	add_bob(&store);

	assert!(store.is_static("alice"), "static account reports true");
	assert!(!store.is_static("bob"), "dynamic account reports false");
	assert!(!store.is_static("ghost"), "unknown account reports false");
}

/// An `accounts.toml` written before `quota_bytes` existed still loads:
/// the field's `#[serde(default)]` keeps the on-disk format backward
/// compatible and the dynamic quota falls through to the server default.
#[test]
fn accounts_toml_without_quota_bytes_still_loads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let text = r#"
[[accounts]]
name = "legacy"
addresses = ["legacy@example.org"]
password_hash = "stub"
"#;
	std::fs::write(dir.path().join("accounts.toml"), text).expect("write");
	let store = open_store(dir.path());
	let directory = store.handle().current();
	assert_eq!(
		directory.resolve(&Address::parse("legacy@example.org").expect("a")),
		Resolution::Account("legacy".to_string())
	);
	assert_eq!(
		directory.quota_for("legacy"),
		None,
		"missing quota_bytes means the server default applies"
	);
}
