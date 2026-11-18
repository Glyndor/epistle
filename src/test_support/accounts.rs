//! A real account store for the tests that need the directory a running
//! server sees after `epistle account disable` or a credential reset: the
//! store's own handle, swapped by the store's own mutators.

use std::path::Path;

use crate::directory_store::credential_reset::hash_digest;
use crate::directory_store::{AccountStore, DynamicAccount, ResetTarget};

use super::fixtures;

/// A store on `dir` holding `names`, each owning `<name>@example.org` and
/// signing in with [`fixtures::password`].
pub(crate) fn store(dir: &Path, names: &[&str]) -> AccountStore {
	let store = AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	for name in names {
		store
			.add(DynamicAccount {
				name: (*name).to_string(),
				addresses: vec![format!("{name}@example.org")],
				password_hash: crate::smtp::auth::tests::base::hash(fixtures::password()),
				..DynamicAccount::default()
			})
			.expect("add account");
	}
	store
}

/// Disable `name` the way `epistle account disable` does.
pub(crate) fn disable(store: &AccountStore, name: &str) {
	let was_disabled = store.set_disabled(name, true).expect("disable");
	assert!(!was_disabled, "{name} was already disabled");
	assert!(store.is_locked(name));
}

/// Reset the credentials of `name` the way `epistle rotate` does, leaving it
/// to wait for an administrator to set new ones.
pub(crate) fn reset(store: &AccountStore, name: &str) {
	let digest = hash_digest(&store.dynamic_account(name).expect(name).password_hash);
	let placeholder = crate::smtp::auth::tests::base::hash(&fixtures::fresh_secret());
	let target = ResetTarget {
		name: name.to_string(),
		digest,
	};
	let reset = store
		.reset_credentials(&[target], &placeholder)
		.expect("reset");
	assert_eq!(reset, [name], "the reset did not reach {name}");
}
