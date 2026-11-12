//! Enabling and disabling aliases in the account store.

use super::base::*;
use super::*;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

pub(super) fn alias_for_team() -> crate::config::Alias {
	crate::config::Alias {
		address: "team@example.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	}
}

pub(super) fn seed(store: AccountStore) -> AccountStore {
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
			send: None,
			receive: None,
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: None,
			catch_all: vec!["example.org".to_string()],
			quota_bytes: None,
			forward: Vec::new(),
			forward_keep_local: true,
			display_name: None,
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
