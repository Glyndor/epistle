//! The switches reach the directory the server runs on: a dynamic account
//! switched by the mutator and a static account switched in the
//! configuration, both after the rebuild.

use std::path::Path;

use super::*;
use crate::smtp::address::Address;
use crate::smtp::auth::tests::base::{fixture_password, hash};
use crate::smtp::directory::Resolution;

fn static_relay(send: Option<bool>, receive: Option<bool>) -> Account {
	Account {
		send,
		receive,
		display_name: None,
		name: "relay".to_string(),
		addresses: vec!["relay@example.org".to_string()],
		password_hash: Some(hash(fixture_password())),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

fn open(dir: &Path, relay: Account) -> AccountStore {
	let store = AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![relay],
	)
	.expect("open store");
	store
		.add(DynamicAccount {
			name: "app".to_string(),
			addresses: vec!["app@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..DynamicAccount::default()
		})
		.expect("add app");
	store
}

fn address(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

#[test]
fn switching_a_dynamic_account_off_reaches_the_running_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path(), static_relay(None, None));
	let directory = store.handle().current();
	assert!(directory.can_send("app") && directory.receives("app"));

	store.set_switch("app", Switch::Send, false).expect("send");
	store
		.set_switch("app", Switch::Receive, false)
		.expect("receive");
	let directory = store.handle().current();
	assert!(!directory.can_send("app"));
	assert_eq!(
		directory.resolve(&address("app@example.org")),
		Resolution::UnknownUser
	);

	store
		.set_switch("app", Switch::Send, true)
		.expect("send on");
	store
		.set_switch("app", Switch::Receive, true)
		.expect("receive on");
	let directory = store.handle().current();
	assert!(directory.can_send("app"));
	assert_eq!(
		directory.resolve(&address("app@example.org")),
		Resolution::Account("app".to_string())
	);
}

#[test]
fn a_static_account_switched_in_the_configuration_reaches_the_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path(), static_relay(Some(false), Some(false)));
	let directory = store.handle().current();
	assert!(!directory.can_send("relay"));
	assert_eq!(
		directory.resolve(&address("relay@example.org")),
		Resolution::UnknownUser
	);
	assert!(directory.can_send("app"), "the other account is untouched");
}

#[test]
fn a_static_account_cannot_be_switched_by_the_mutator() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path(), static_relay(None, None));
	assert!(matches!(
		store.set_switch("relay", Switch::Send, false),
		Err(StoreError::NotFound(_))
	));
}
