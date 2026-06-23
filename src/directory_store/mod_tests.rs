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
