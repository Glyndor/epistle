//! `replace_account` holds a replacement to the checks `add` applies: a
//! served domain, and no address another route already owns.

use super::*;
use crate::smtp::auth::tests::base::{fixture_password, hash};

fn store(dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_aliases(vec![crate::config::Alias {
		address: "team@example.org".to_string(),
		members: vec!["bob@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	}])
}

fn account(name: &str, address: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: hash(fixture_password()),
		..DynamicAccount::default()
	}
}

fn with_bob(dir: &std::path::Path) -> AccountStore {
	let store = store(dir);
	store
		.add(account("bob", "bob@example.org"))
		.expect("add bob");
	store
}

#[test]
fn replace_refuses_an_alias_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = with_bob(dir.path());
	let result = store.replace_account("bob", account("bob", "Team@example.org"));
	assert!(
		matches!(result, Err(StoreError::Duplicate(_))),
		"{result:?}"
	);
	assert_eq!(
		store.dynamic_account("bob").unwrap().addresses,
		["bob@example.org"]
	);
}

#[test]
fn replace_refuses_a_masked_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = with_bob(dir.path());
	store
		.add(account("carol", "carol@example.org"))
		.expect("add carol");
	let masked = store
		.add_masked("carol", "shop", "example.org", 1)
		.expect("masked")
		.address;
	let result = store.replace_account("bob", account("bob", &masked));
	assert!(
		matches!(result, Err(StoreError::Duplicate(_))),
		"{result:?}"
	);
}

#[test]
fn replace_refuses_a_domain_the_server_does_not_serve() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = with_bob(dir.path());
	let result = store.replace_account("bob", account("bob", "bob@elsewhere.example"));
	assert!(matches!(result, Err(StoreError::Invalid(_))), "{result:?}");
}

#[test]
fn replace_still_takes_a_free_address_and_keeps_its_own() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = with_bob(dir.path());
	let mut next = account("bob", "bob@example.org");
	next.addresses.push("robert@example.org".to_string());
	store.replace_account("bob", next).expect("free address");
	assert_eq!(
		store.dynamic_account("bob").unwrap().addresses,
		["bob@example.org", "robert@example.org"]
	);
}
