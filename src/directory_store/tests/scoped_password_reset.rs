//! A password set for a caller that was authorized before the password was
//! derived is checked again about the account as it is under the store's
//! lock: an account that moved to another tenant in between keeps its
//! credentials.

use super::*;

const PRIOR: &str = "$argon2id$prior-hash";

fn in_tenant_a(account: &DynamicAccount) -> bool {
	!account.addresses.is_empty()
		&& account
			.addresses
			.iter()
			.all(|address| address.ends_with("@a.example"))
}

fn two_tenants(dir: &std::path::Path) -> AccountStore {
	let store = AccountStore::open(
		dir,
		vec!["a.example".to_string(), "b.example".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	store
		.add(DynamicAccount {
			name: "victim".to_string(),
			addresses: vec!["victim@a.example".to_string()],
			password_hash: PRIOR.to_string(),
			..DynamicAccount::default()
		})
		.expect("add victim");
	store
}

fn stored_hash(store: &AccountStore) -> String {
	store
		.dynamic_account("victim")
		.expect("victim")
		.password_hash
}

#[test]
fn scoped_password_reset_follows_the_account_to_its_new_tenant() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = two_tenants(dir.path());
	// Inside the reach it goes through.
	store
		.set_password_hash_if("victim", "$argon2id$first".to_string(), None, in_tenant_a)
		.expect("in reach");
	assert_eq!(stored_hash(&store), "$argon2id$first");
	// The account moves to tenant B after the caller was authorized for A.
	let mut moved = store.dynamic_account("victim").expect("victim");
	moved.addresses = vec!["victim@b.example".to_string()];
	store
		.replace_account("victim", moved, None)
		.expect("move to b");
	let before = stored_hash(&store);
	let refused = store.set_password_hash_if(
		"victim",
		"$argon2id$attacker".to_string(),
		None,
		in_tenant_a,
	);
	assert!(
		matches!(refused, Err(StoreError::NotFound(_))),
		"{refused:?}"
	);
	assert_eq!(stored_hash(&store), before, "the credentials are untouched");
}

#[test]
fn scoped_password_reset_leaves_an_unconditional_caller_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = two_tenants(dir.path());
	store
		.set_password_hash("victim", "$argon2id$local".to_string(), None)
		.expect("local");
	assert_eq!(stored_hash(&store), "$argon2id$local");
}

#[test]
fn scoped_password_reset_guards_replace_account_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = two_tenants(dir.path());
	let mut moved = store.dynamic_account("victim").expect("victim");
	moved.addresses = vec!["victim@b.example".to_string()];
	store
		.replace_account("victim", moved.clone(), None)
		.expect("move to b");
	let mut attempt = moved;
	attempt.display_name = Some("taken over".to_string());
	let refused = store.replace_account_if("victim", attempt, None, in_tenant_a);
	assert!(
		matches!(refused, Err(StoreError::NotFound(_))),
		"{refused:?}"
	);
	assert_eq!(
		store
			.dynamic_account("victim")
			.expect("victim")
			.display_name,
		None
	);
}

#[test]
fn scoped_password_reset_guards_every_change_of_a_patch() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = two_tenants(dir.path());
	let mut moved = store.dynamic_account("victim").expect("victim");
	moved.addresses = vec!["victim@b.example".to_string()];
	store
		.replace_account("victim", moved, None)
		.expect("move to b");
	let changes = AccountChanges {
		disabled: Some(true),
		password: None,
		display_name: Some("renamed".to_string()),
	};
	let refused = store.change_account_if("victim", changes, in_tenant_a);
	assert!(
		matches!(refused, Err(StoreError::NotFound(_))),
		"{refused:?}"
	);
	let after = store.dynamic_account("victim").expect("victim");
	assert!(!after.disabled);
	assert_eq!(after.display_name, None);
}

#[test]
fn scoped_password_reset_writes_the_changes_of_a_patch_together() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = two_tenants(dir.path());
	let changes = AccountChanges {
		disabled: Some(true),
		password: Some(NewPassword {
			hash: "$argon2id$together".to_string(),
			scram: None,
		}),
		display_name: Some(" Together ".to_string()),
	};
	store
		.change_account_if("victim", changes, in_tenant_a)
		.expect("change");
	let after = store.dynamic_account("victim").expect("victim");
	assert!(after.disabled);
	assert_eq!(after.password_hash, "$argon2id$together");
	assert_eq!(after.display_name.as_deref(), Some("Together"));
}
