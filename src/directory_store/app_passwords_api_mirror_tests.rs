//! `add_app_password` and `remove_all_app_passwords` rebuild the
//! in-memory mirror from the disk state after their write, so a
//! credential another process wrote while the server's `AccountStore`
//! was open is not lost from the mirror. The file always keeps it,
//! because the disk store rereads under the `flock`; without the
//! rebuild the server would refuse that credential until a restart.
//!
//! Lives in a sibling so `app_passwords_api.rs` stays under the
//! per-file line budget.

use crate::directory_store::{AccountStore, AppPassword, AppPasswordStore};
use crate::smtp::auth::tests::{fixture_password, hash};

/// A data dir with dynamic accounts `alice` and `bob`, and the server's
/// store opened over it before anything else writes.
fn server_store() -> (tempfile::TempDir, AccountStore) {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	for name in ["alice", "bob"] {
		store
			.add(crate::directory_store::DynamicAccount {
				name: name.to_string(),
				addresses: vec![format!("{name}@example.org")],
				password_hash: hash(fixture_password()),
				..Default::default()
			})
			.expect("add account");
	}
	(dir, store)
}

fn app(label: &str) -> AppPassword {
	AppPassword {
		label: label.to_string(),
		hash: hash(fixture_password()),
		expires_at: None,
		ip_cidr: None,
		save_sent: None,
	}
}

/// Another process adds `label` for `account` through its own store.
fn sibling_adds(data_dir: &std::path::Path, account: &str, label: &str) {
	AppPasswordStore::open(data_dir)
		.expect("open sibling")
		.add(account, app(label))
		.expect("sibling add");
}

fn labels(store: &AccountStore, account: &str) -> Vec<String> {
	store
		.for_account(account)
		.into_iter()
		.map(|app| app.label)
		.collect()
}

#[test]
fn add_keeps_a_credential_a_sibling_wrote_after_the_store_opened() {
	let (dir, store) = server_store();
	sibling_adds(dir.path(), "alice", "phone");
	store
		.add_app_password("alice", app("tablet"))
		.expect("server add");
	assert_eq!(
		labels(&store, "alice"),
		vec!["phone", "tablet"],
		"the mirror must hold the sibling's credential and the new one"
	);
}

#[test]
fn removal_keeps_another_account_s_credential_a_sibling_wrote() {
	let (dir, store) = server_store();
	store
		.add_app_password("alice", app("laptop"))
		.expect("server add");
	sibling_adds(dir.path(), "bob", "phone");
	store
		.remove_all_app_passwords("alice")
		.expect("remove alice's credentials");
	assert!(
		labels(&store, "alice").is_empty(),
		"the removed account must keep no credential"
	);
	assert_eq!(
		labels(&store, "bob"),
		vec!["phone"],
		"the mirror must hold the credential the sibling wrote for another account"
	);
}
