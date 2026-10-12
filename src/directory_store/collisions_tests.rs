//! Collisions between owners once addresses are lowercased: the first owner
//! keeps the address, nothing is merged or deleted, and both are named.

use super::super::*;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

const ACCOUNTS_TOML: &str = r#"
[[accounts]]
name = "other"
addresses = ["other@example.org", "ANA@example.org"]
password_hash = "$argon2id$x"

[[accounts]]
name = "first"
addresses = ["Ärger@example.org"]
password_hash = "$argon2id$x"

[[accounts]]
name = "second"
addresses = ["ärger@example.org", "Team@Example.org"]
password_hash = "$argon2id$x"
"#;

fn store(dir: &std::path::Path) -> AccountStore {
	std::fs::write(dir.join("accounts.toml"), ACCOUNTS_TOML).expect("write");
	let ana = Account {
		display_name: None,
		name: "ana".to_string(),
		addresses: vec!["ana@example.org".to_string()],
		password_hash: None,
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let team = crate::config::Alias {
		address: "team@example.org".to_string(),
		members: vec!["ana@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	};
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![ana],
	)
	.expect("open")
	.with_aliases(vec![team])
}

fn resolve(store: &AccountStore, raw: &str) -> Resolution {
	store
		.handle()
		.current()
		.resolve(&Address::parse(raw).expect("address"))
}

#[test]
fn every_collision_is_named_with_both_owners() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	assert_eq!(
		store.address_collisions(),
		vec![
			"address ana@example.org is claimed by account \"ana\" (mail.toml) and by \
			 account \"other\" (accounts.toml); account \"ana\" (mail.toml) keeps it",
			"address ärger@example.org is claimed by account \"first\" (accounts.toml) and by \
			 account \"second\" (accounts.toml); account \"first\" (accounts.toml) keeps it",
			"address team@example.org is claimed by account \"second\" (accounts.toml) and by \
			 alias team@example.org (mail.toml); account \"second\" (accounts.toml) keeps it",
		]
	);
}

#[test]
fn the_first_owner_keeps_the_address_and_nothing_is_deleted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	assert_eq!(
		resolve(&store, "ANA@example.org"),
		Resolution::Account("ana".to_string())
	);
	assert_eq!(
		resolve(&store, "ÄRGER@example.org"),
		Resolution::Account("first".to_string())
	);
	assert_eq!(
		store.dynamic("second").expect("second").addresses,
		vec!["ärger@example.org", "team@example.org"],
		"the later claim stays on the account"
	);
	assert_eq!(
		resolve(&store, "other@example.org"),
		Resolution::Account("other".to_string())
	);
}
