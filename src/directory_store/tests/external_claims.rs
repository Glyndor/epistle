//! An address or a name held by a SQL or LDAP account cannot be taken by a
//! dynamic account: the directory keeps the last writer, so the dynamic
//! account would otherwise start receiving that mailbox's mail.

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

fn dynamic(name: &str, address: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: "$argon2id$stub".to_string(),
		..DynamicAccount::default()
	}
}

fn with_directory_accounts(store: &AccountStore) {
	store.set_ldap_accounts(vec![LdapAccount {
		name: "ldap-user".to_string(),
		addresses: vec!["ldap-user@example.org".to_string()],
	}]);
	store.set_sql_accounts(vec![SqlAccount {
		name: "sql-user".to_string(),
		addresses: vec!["sql-user@example.org".to_string()],
		password_hash: None,
	}]);
}

#[test]
fn add_refuses_an_address_held_by_a_directory_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	with_directory_accounts(&store);
	for address in ["ldap-user@example.org", "SQL-User@example.org"] {
		let result = store.add(dynamic("intruder", address));
		assert!(matches!(result, Err(StoreError::Duplicate(_))), "{address}");
	}
	let resolved = store
		.handle()
		.current()
		.resolve(&Address::parse("ldap-user@example.org").expect("address"));
	assert_eq!(resolved, Resolution::Account("ldap-user".to_string()));
}

#[test]
fn add_refuses_a_name_held_by_a_directory_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	with_directory_accounts(&store);
	let result = store.add(dynamic("ldap-user", "fresh@example.org"));
	assert!(matches!(result, Err(StoreError::Duplicate(_))));
}

#[test]
fn replace_and_add_address_refuse_a_directory_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store
		.add(dynamic("bob", "bob@example.org"))
		.expect("add bob");
	with_directory_accounts(&store);
	let replaced = store.replace_account("bob", dynamic("bob", "ldap-user@example.org"), None);
	assert!(matches!(replaced, Err(StoreError::Duplicate(_))));
	let added = store.add_address("bob", "sql-user@example.org");
	assert!(matches!(added, Err(StoreError::Duplicate(_))));
}

#[test]
fn a_tagged_form_of_a_directory_address_is_taken_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	with_directory_accounts(&store);
	let result = store.add(dynamic("intruder", "ldap-user+shop@example.org"));
	assert!(matches!(result, Err(StoreError::Duplicate(_))));
	store
		.add(dynamic("bob", "bob@example.org"))
		.expect("add bob");
	let replaced = store.replace_account("bob", dynamic("bob", "sql-user+x@example.org"));
	assert!(matches!(replaced, Err(StoreError::Duplicate(_))));
	let added = store.add_address("bob", "Ldap-User+Shop@example.org");
	assert!(matches!(added, Err(StoreError::Duplicate(_))));
	let resolved = store
		.handle()
		.current()
		.resolve(&Address::parse("ldap-user+shop@example.org").expect("address"));
	assert_eq!(resolved, Resolution::Account("ldap-user".to_string()));
}

#[test]
fn a_directory_name_in_another_case_is_taken_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.set_ldap_accounts(vec![LdapAccount {
		name: "Alice".to_string(),
		addresses: vec!["jsmith@example.org".to_string()],
	}]);
	let result = store.add(dynamic("alice", "fresh@example.org"));
	assert!(matches!(result, Err(StoreError::Duplicate(_))), "{result:?}");
}
