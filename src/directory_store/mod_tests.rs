//! Tests for the runtime account store and directory handle.

use super::*;
use crate::smtp::directory::Resolution;

fn static_account() -> Account {
	Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: None,
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

fn dynamic(name: &str, address: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: "$argon2id$stub".to_string(),
		scram: None,
		totp_secret: None,
		disabled: false,
		allowed_protocols: None,
	}
}

fn resolves(handle: &DirectoryHandle, raw: &str) -> Resolution {
	handle
		.current()
		.resolve(&Address::parse(raw).expect("address"))
}

#[test]
fn add_swaps_the_directory_and_persists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	let handle = store.handle();

	assert_eq!(
		resolves(&handle, "bob@example.org"),
		Resolution::UnknownUser
	);
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	assert_eq!(
		resolves(&handle, "bob@example.org"),
		Resolution::Account("bob".to_string())
	);

	// A fresh store sees the persisted account.
	let reopened = open_store(dir.path());
	assert_eq!(
		resolves(&reopened.handle(), "bob@example.org"),
		Resolution::Account("bob".to_string())
	);
}

#[test]
fn rejects_duplicates_and_foreign_domains() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());

	// Static name and address are taken.
	assert!(matches!(
		store.add(dynamic("alice", "alice2@example.org")),
		Err(StoreError::Duplicate(_))
	));
	assert!(matches!(
		store.add(dynamic("bob", "ALICE@example.org")),
		Err(StoreError::Duplicate(_))
	));
	assert!(matches!(
		store.add(dynamic("bob", "bob@elsewhere.example")),
		Err(StoreError::Invalid(_))
	));
	assert!(matches!(
		store.add(dynamic("Bad Name", "bob@example.org")),
		Err(StoreError::Invalid(_))
	));
}

#[test]
fn remove_only_dynamic_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.add(dynamic("bob", "bob@example.org")).expect("add");

	assert!(matches!(
		store.remove("alice"),
		Err(StoreError::NotFound(_))
	));
	store.remove("bob").expect("remove");
	assert_eq!(
		resolves(&store.handle(), "bob@example.org"),
		Resolution::UnknownUser
	);
}

#[test]
fn password_change_swaps_credentials() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.add(dynamic("bob", "bob@example.org")).expect("add");

	let real_hash = crate::smtp::auth::tests::hash("secret");
	store
		.set_password_hash("bob", real_hash, None)
		.expect("set password");
	let directory = store.handle().current();
	let (account, hash) = directory.credentials("bob").expect("credentials");
	assert_eq!(account, "bob");
	assert!(crate::smtp::auth::verify_password(hash, "secret"));
}

#[test]
fn ldap_accounts_resolve_and_refresh_with_static_precedence() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());

	// An LDAP-sourced account resolves like any other source.
	store.set_ldap_accounts(vec![LdapAccount {
		name: "carol".to_string(),
		addresses: vec!["carol@example.org".to_string()],
	}]);
	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		Resolution::Account("carol".to_string())
	);

	// Static config wins over an LDAP account claiming the same address.
	store.set_ldap_accounts(vec![LdapAccount {
		name: "ldap-alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
	}]);
	assert_eq!(
		resolves(&store.handle(), "alice@example.org"),
		Resolution::Account("alice".to_string())
	);

	// A refresh replaces the previous LDAP set entirely.
	store.set_ldap_accounts(Vec::new());
	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		Resolution::UnknownUser
	);
}

#[test]
fn account_views_mark_origin() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let views = store.account_views();
	assert_eq!(views.len(), 2);
	assert_eq!(views[0].0, "alice");
	assert!(!views[0].2);
	assert_eq!(views[1].0, "bob");
	assert!(views[1].2);
}

#[test]
fn an_ldap_account_whose_name_escapes_the_data_dir_is_dropped() {
	// LDAP rows take the same route as SQL ones: straight into the store, with
	// the name later used as a directory under `<data_dir>/accounts/`.
	// `mailbox_dir` checks the mailbox name and trusts the account, so a
	// directory attribute holding `../..` escaped the data dir.
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	store.set_ldap_accounts(vec![
		crate::directory_store::LdapAccount {
			name: "../../etc".to_string(),
			addresses: vec!["escape@example.org".to_string()],
		},
		crate::directory_store::LdapAccount {
			name: "ok".to_string(),
			addresses: vec!["ok@example.org".to_string()],
		},
	]);
	let resolve = |address: &str| {
		store
			.handle()
			.current()
			.resolve(&crate::smtp::address::Address::parse(address).expect("address"))
	};
	assert!(
		matches!(resolve("ok@example.org"), crate::smtp::directory::Resolution::Account(ref n) if n == "ok"),
	);
	assert!(
		!matches!(
			resolve("escape@example.org"),
			crate::smtp::directory::Resolution::Account(_)
		),
		"a name that would escape the data dir must not become an account",
	);
}

// Integration tests for the alias disabled-overlay wiring through
// `AccountStore`. The directory-level tests in
// `src/smtp/directory_alias_tests.rs` cover `Directory`'s behaviour in
// isolation; this module covers the AccountStore path that rebuilds the
// directory from the disabled set on every write.

fn alias_for_team() -> crate::config::Alias {
	crate::config::Alias {
		address: "team@example.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	}
}

fn seed(store: AccountStore) -> AccountStore {
	store.with_aliases(vec![alias_for_team()])
}

#[test]
fn set_alias_enabled_disables_then_re_enables() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = seed(open_store(dir.path()));
	let handle = store.handle();

	// Enabled: the alias resolves.
	assert!(matches!(
		handle
			.current()
			.resolve(&Address::parse("team@example.org").expect("a")),
		Resolution::Alias(_)
	));

	// Disabled: the alias falls out, the next step runs.
	let was = store
		.set_alias_enabled("team@example.org", false)
		.expect("disable");
	assert!(!was);
	assert!(store.alias_is_disabled("team@example.org"));
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("team@example.org").expect("a")),
		Resolution::UnknownUser
	);

	// Re-enabled: the alias is back.
	let was = store
		.set_alias_enabled("team@example.org", true)
		.expect("enable");
	assert!(was);
	assert!(!store.alias_is_disabled("team@example.org"));
	assert!(matches!(
		handle
			.current()
			.resolve(&Address::parse("team@example.org").expect("a")),
		Resolution::Alias(_)
	));
}

#[test]
fn disabled_alias_falls_through_to_catch_all_in_account_store() {
	// Build a store with a catch-all on the domain AND the alias seeded.
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![crate::config::Account {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: None,
			catch_all: vec!["example.org".to_string()],
			quota_bytes: None,
			forward: Vec::new(),
			forward_keep_local: true,
			allowed_protocols: None,
		}],
	)
	.expect("open store");
	let store = store.with_aliases(vec![crate::config::Alias {
		address: "team@example.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	}]);
	let handle = store.handle();

	// Enabled: the alias step wins on `team@example.org`.
	assert!(matches!(
		handle
			.current()
			.resolve(&Address::parse("team@example.org").expect("a")),
		Resolution::Alias(_)
	));

	// Disabled: the alias falls out and the catch-all picks up the
	// address.
	store
		.set_alias_enabled("team@example.org", false)
		.expect("disable");
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("team@example.org").expect("a")),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn disabled_alias_persists_across_restart_in_account_store() {
	let dir = tempfile::tempdir().expect("tempdir");
	{
		let store = seed(open_store(dir.path()));
		store
			.set_alias_enabled("team@example.org", false)
			.expect("disable");
	}
	let reopened = open_store(dir.path());
	assert!(reopened.alias_is_disabled("team@example.org"));
}

/// A static account with `allowed_protocols` set propagates into the
/// directory the store rebuilds, so the gate in
/// `Directory::authenticate_with_ip` sees the restriction. The store
/// pulls the option from the static config; the directory unit tests
/// in `smtp::directory::protocol_tests` exercise the gate directly.
#[test]
fn static_allowed_protocols_propagates_to_directory() {
	use crate::config::Protocol;
	let dir = tempfile::tempdir().expect("tempdir");
	let static_account = Account {
		name: "service".to_string(),
		addresses: vec!["service@example.org".to_string()],
		password_hash: Some(crate::smtp::auth::tests::hash("s3cret")),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: Some(vec![Protocol::Api]),
	};
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![static_account],
	)
	.expect("open store");
	let directory = store.handle().current();
	// The static config's allowlist flows into the rebuilt directory:
	// the allowed protocol admits, the unlisted one rejects.
	assert_eq!(
		directory
			.authenticate("service", "s3cret", Protocol::Api)
			.as_deref(),
		Some("service"),
	);
	assert!(
		directory
			.authenticate("service", "s3cret", Protocol::Imaps)
			.is_none(),
		"static allowed_protocols must restrict authentication"
	);
}

/// A dynamic account with `allowed_protocols` set propagates into the
/// directory after `add` swaps the rebuilt handle. The store rebuilds
/// the directory on every mutation (see `AccountStore::add`); this
/// test pins that the rebuild also picks up the dynamic account's
/// allowlist, not just the static one.
#[test]
fn dynamic_allowed_protocols_propagates_to_directory() {
	use crate::config::Protocol;
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	let mut dynamic_account = dynamic("service", "service@example.org");
	// The `dynamic` helper seeds a stub hash so other tests can poke
	// `set_password_hash`; replace it with a real argon2id hash so the
	// directory's password check matches the test password.
	dynamic_account.password_hash = crate::smtp::auth::tests::hash("secret");
	dynamic_account.allowed_protocols = Some(vec![Protocol::Api]);
	store.add(dynamic_account).expect("add");
	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate("service", "secret", Protocol::Api)
			.as_deref(),
		Some("service"),
	);
	assert!(
		directory
			.authenticate("service", "secret", Protocol::Imaps)
			.is_none(),
		"dynamic allowed_protocols must restrict authentication"
	);
}
