//! The address writes decide from the account file they read under its lock. A
//! second handle on the same directory stands for another process: what it
//! writes is not in the first handle's memory.

use std::collections::HashMap;
use std::path::Path;

use super::*;
use crate::limits::test_support::shared_from;

/// `example.net` caps an account at two addresses, and the tenant `acme` owns
/// `example.com` and holds one account.
const CONFIG: &str = "domains = [\"example.com\", \"example.org\", \"example.net\"]\n\
	 [[tenant]]\nname = \"acme\"\ndomains = [\"example.com\"]\nmax_accounts = 1\n\
	 [[limit_scope]]\ndomain = \"example.net\"\nmax_addresses_per_account = 2\n";

fn open(dir: &Path) -> AccountStore {
	AccountStore::open(
		dir,
		["example.com", "example.org", "example.net"]
			.map(String::from)
			.to_vec(),
		HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_limits(shared_from(CONFIG))
}

/// A directory with `bob` and `eve`, and two handles on it.
fn two_handles() -> (tempfile::TempDir, AccountStore, AccountStore) {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = open(dir.path());
	for name in ["bob", "eve"] {
		first
			.add(DynamicAccount {
				name: name.to_string(),
				addresses: vec![format!("{name}@example.org")],
				password_hash: "$argon2id$stub".to_string(),
				..DynamicAccount::default()
			})
			.expect("add");
	}
	let second = open(dir.path());
	(dir, first, second)
}

fn held(store: &AccountStore, name: &str) -> usize {
	store.dynamic(name).expect("account").addresses.len()
}

#[test]
fn the_tenants_cap_counts_what_another_process_wrote() {
	let (_dir, first, second) = two_handles();
	second
		.add_address("eve", "eve@example.com")
		.expect("the last place");
	let refused = first.add_address("bob", "bob@example.com");
	assert!(
		matches!(&refused, Err(StoreError::TenantCapped(text)) if text.contains("acme")),
		"{refused:?}"
	);
	assert_eq!(held(&first, "bob"), 1);
	// The account that holds the place keeps adding there.
	first
		.add_address("eve", "more@example.com")
		.expect("already counted");
}

#[test]
fn the_address_cap_is_resolved_over_the_domains_the_file_holds() {
	let (_dir, first, second) = two_handles();
	second
		.add_address("bob", "bob@example.net")
		.expect("the second address");
	// Only the file says that `bob` is in `example.net`, whose cap is two.
	let refused = first.add_address("bob", "third@example.org");
	assert!(matches!(refused, Err(StoreError::Capped(_))), "{refused:?}");
}

#[test]
fn the_rule_of_the_caller_sees_the_account_as_the_file_has_it() {
	let (_dir, first, second) = two_handles();
	second
		.add_address("bob", "late@example.org")
		.expect("another process");
	let mut seen = Vec::new();
	first
		.add_address_if("bob", "new@example.org", |account| {
			seen = account.addresses.clone();
			true
		})
		.expect("added");
	assert_eq!(seen, ["bob@example.org", "late@example.org"]);
	first
		.remove_address_if("bob", "new@example.org", |account| {
			seen = account.addresses.clone();
			true
		})
		.expect("removed");
	assert_eq!(seen.len(), 3);
}

/// A refusal answers like an account that is not there, before anything is
/// said about the address, and writes nothing.
#[test]
fn a_refusal_of_the_caller_comes_before_any_answer_about_the_address() {
	let (_dir, store, _) = two_handles();
	for address in [
		"new@example.org",
		"eve@example.org",
		"bob@example.org",
		"x@not-hosted.example",
	] {
		let refused = store.add_address_if("bob", address, |_| false);
		assert!(
			matches!(refused, Err(StoreError::NotFound(_))),
			"{address}: {refused:?}"
		);
	}
	for address in ["bob@example.org", "nobody@example.org"] {
		let refused = store.remove_address_if("bob", address, |_| false);
		assert!(
			matches!(refused, Err(StoreError::NotFound(_))),
			"{address}: {refused:?}"
		);
	}
	assert_eq!(
		store.dynamic("bob").expect("bob").addresses,
		["bob@example.org"]
	);
}

/// An account of the configuration file holds a place of its tenant like any
/// other.
#[test]
fn the_tenants_cap_counts_the_accounts_of_the_configuration_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let fixed = crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: "root".to_string(),
		addresses: vec!["root@example.com".to_string()],
		password_hash: Some("$argon2id$stub".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = AccountStore::open(
		dir.path(),
		["example.com", "example.org", "example.net"]
			.map(String::from)
			.to_vec(),
		HashMap::new(),
		vec![fixed],
	)
	.expect("open store")
	.with_limits(shared_from(CONFIG));
	store
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: "$argon2id$stub".to_string(),
			..DynamicAccount::default()
		})
		.expect("add");
	let refused = store.add_address("bob", "bob@example.com");
	assert!(
		matches!(refused, Err(StoreError::TenantCapped(_))),
		"{refused:?}"
	);
	assert_eq!(held(&store, "bob"), 1);
}
