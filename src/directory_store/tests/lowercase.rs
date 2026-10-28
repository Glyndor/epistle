//! Dynamic accounts store the lowercase form of every address, forward
//! target and catch-all domain, whatever case the caller wrote, and an
//! `accounts.toml` written before that rule is read in lowercase and saved
//! in lowercase on the next write.

use std::path::Path;

use super::*;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

fn open_store(dir: &Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
}

fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| a.to_string()).collect(),
		password_hash: "$argon2id$x".to_string(),
		..DynamicAccount::default()
	}
}

fn resolve(store: &AccountStore, raw: &str) -> Resolution {
	store
		.handle()
		.current()
		.resolve(&Address::parse(raw).expect("address"))
}

#[test]
fn add_stores_a_lowercase_name_and_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store
		.add(account(
			"Alice",
			&["Alice.Smith@Example.ORG", " ÄRGER@example.org "],
		))
		.expect("add");
	let stored = store
		.dynamic("alice")
		.expect("stored under the lowercase name");
	assert_eq!(
		stored.addresses,
		vec!["alice.smith@example.org", "ärger@example.org"]
	);
	let on_disk = std::fs::read_to_string(dir.path().join("accounts.toml")).expect("file");
	assert!(on_disk.contains("\"alice.smith@example.org\""), "{on_disk}");
	assert!(!on_disk.contains("Alice"), "{on_disk}");
}

#[test]
fn add_refuses_an_address_that_differs_only_in_case_from_another_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store
		.add(account("ana", &["ÄNA@example.org"]))
		.expect("add ana");
	let error = store
		.add(account("other", &["äna@example.org"]))
		.expect_err("same mailbox");
	assert!(
		matches!(&error, StoreError::Duplicate(what) if what == "äna@example.org"),
		"{error}"
	);
}

#[test]
fn delivery_to_any_spelling_lands_in_the_same_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store
		.add(account(
			"alice",
			&["Alice.Smith@Example.ORG", "Ärger@example.org"],
		))
		.expect("add");
	assert_eq!(
		resolve(&store, "ALICE.SMITH@EXAMPLE.ORG"),
		Resolution::Account("alice".to_string())
	);
	assert_eq!(
		resolve(&store, "ÄRGER@example.org"),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn address_forward_and_catch_all_mutators_store_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store
		.add(account("bob", &["bob@example.org"]))
		.expect("add");
	// Each write is checked on its own: the next write would rewrite the
	// whole file in lowercase and hide a mutator that stored what it got.
	let on_disk = || std::fs::read_to_string(dir.path().join("accounts.toml")).expect("file");
	store
		.add_address("bob", "Robert@Example.ORG")
		.expect("address");
	assert!(!on_disk().contains("Robert"), "{}", on_disk());
	store
		.add_forward("bob", "Bob@Elsewhere.Example")
		.expect("forward");
	assert!(!on_disk().contains("Elsewhere"), "{}", on_disk());
	store
		.add_catch_all("bob", "EXAMPLE.org")
		.expect("catch-all");
	assert!(!on_disk().contains("EXAMPLE"), "{}", on_disk());
	let stored = store.dynamic("bob").expect("bob");
	assert_eq!(
		stored.addresses,
		vec!["bob@example.org", "robert@example.org"]
	);
	assert_eq!(stored.forward, vec!["bob@elsewhere.example"]);
	assert_eq!(stored.catch_all, vec!["example.org"]);
	store
		.remove_address("bob", "ROBERT@example.org")
		.expect("remove by another spelling");
	store
		.remove_forward("bob", "BOB@elsewhere.example")
		.expect("remove forward by another spelling");
	let stored = store.dynamic("bob").expect("bob");
	assert_eq!(stored.addresses, vec!["bob@example.org"]);
	assert!(stored.forward.is_empty());
}

const MIXED_CASE_FILE: &str = r#"
[[accounts]]
name = "carol"
addresses = ["Carol@Example.ORG"]
password_hash = "$argon2id$x"
forward = ["Carol@Elsewhere.Example"]
catch_all = ["Example.ORG"]

[[accounts]]
name = "dave"
addresses = ["dave@example.org"]
password_hash = "$argon2id$x"
"#;

#[test]
fn an_existing_mixed_case_file_is_read_in_lowercase_and_saved_on_the_next_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("accounts.toml");
	std::fs::write(&path, MIXED_CASE_FILE).expect("write");
	let store = open_store(dir.path());
	let carol = store.dynamic("carol").expect("carol");
	assert_eq!(carol.addresses, vec!["carol@example.org"]);
	assert_eq!(carol.forward, vec!["carol@elsewhere.example"]);
	assert_eq!(carol.catch_all, vec!["example.org"]);
	assert_eq!(
		std::fs::read_to_string(&path).expect("read"),
		MIXED_CASE_FILE,
		"opening never rewrites the file"
	);
	// Any write saves every account in its stored form.
	store
		.set_quota_bytes("dave", Some(1024))
		.expect("touch dave");
	let on_disk = std::fs::read_to_string(&path).expect("read");
	assert!(on_disk.contains("\"carol@example.org\""), "{on_disk}");
	assert!(!on_disk.contains("Carol"), "{on_disk}");
	assert!(!on_disk.contains("Example.ORG"), "{on_disk}");
}

#[test]
fn a_reload_from_a_sibling_process_reads_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.reload_accounts_from(MIXED_CASE_FILE).expect("reload");
	assert_eq!(
		store.dynamic("carol").expect("carol").addresses,
		vec!["carol@example.org"]
	);
}

#[test]
fn a_mixed_case_masked_file_is_read_in_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(
		dir.path().join("masked.json"),
		r#"{"addresses": {"Shop.ABCDEFGH@Example.ORG": {
			"address": "Shop.ABCDEFGH@Example.ORG", "account": "Bob",
			"label": "shop", "created_at": 0, "enabled": true}}}"#,
	)
	.expect("write masked.json");
	let store = open_store(dir.path());
	let listed = store.list_masked("bob");
	assert_eq!(listed.len(), 1);
	assert_eq!(listed[0].address, "shop.abcdefgh@example.org");
	assert_eq!(
		resolve(&store, "SHOP.abcdefgh@example.org"),
		Resolution::Account("bob".to_string())
	);
}
