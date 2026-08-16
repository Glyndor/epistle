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

#[cfg(unix)]
#[test]
fn accounts_toml_written_with_owner_only_mode() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.add(dynamic("bob", "bob@example.org")).expect("add");

	let path = dir.path().join("accounts.toml");
	let metadata = std::fs::metadata(&path).expect("metadata");
	let mode = metadata.permissions().mode() & 0o7777;
	assert_eq!(
		mode, 0o600,
		"expected 0o600 regardless of umask, got {:o}",
		mode
	);
}

#[cfg(unix)]
#[test]
fn accounts_toml_corrects_legacy_world_readable_mode() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");

	// Pre-create the file with mode 0o644 as if a legacy deployment had run
	// before the fix. AccountStore::open() must tighten it on load.
	let path = dir.path().join("accounts.toml");
	std::fs::write(&path, "").expect("seed file");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("seed mode");

	let store = open_store(dir.path());
	let metadata = std::fs::metadata(&path).expect("metadata after open");
	let mode_after_open = metadata.permissions().mode() & 0o7777;
	assert_eq!(
		mode_after_open, 0o600,
		"open() should have tightened to 0o600, got {:o}",
		mode_after_open
	);

	// And a subsequent persist (via mutation) keeps it 0o600 even if the
	// rename path tries anything funny.
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let mode_after_persist = std::fs::metadata(&path)
		.expect("metadata after persist")
		.permissions()
		.mode()
		& 0o7777;
	assert_eq!(mode_after_persist, 0o600);
}

#[cfg(unix)]
#[test]
fn accounts_toml_load_survives_failed_chmod() {
	// Even when the chmod sweep at open() cannot run, the store must load
	// the existing file. We make the parent directory read-only so the chmod
	// on the file fails with EPERM; the store should still open without
	// panicking, and the test should not error out.
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("accounts.toml");
	std::fs::write(
		&path,
		"[[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\n\
		 password_hash = \"$argon2id$stub\"\ntotp_secret = \"JBSWY3DPEHPK3PXP\"\n",
	)
	.expect("seed");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("seed mode");
	// Strip write on the parent dir so the chmod inside open() fails.
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).expect("lock dir");

	let store = open_store(dir.path());
	// Restore dir perms so the tempdir can clean up the test file.
	let _ = std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755));
	let bob = store
		.handle()
		.current()
		.resolve(&Address::parse("bob@example.org").expect("address"));
	assert_eq!(bob, Resolution::Account("bob".to_string()));
}
