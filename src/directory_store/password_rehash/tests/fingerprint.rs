//! A rewrite of the hash is not a change of the password: a grant bound to
//! the credentials keeps working, and any real change still ends it.

use super::*;
use crate::smtp::auth::cost;

fn rewritten(dir: &Path, cost_in_force: Argon2Cost) -> std::sync::Arc<AccountStore> {
	let store = store_with(dir, hash_at(DEFAULT)).into_shared();
	cost::scoped(cost_in_force, || login(&store, fixtures::password())).expect("signed in");
	store
}

#[test]
fn the_credential_digest_survives_a_rewrite_and_a_second_one() {
	let dir = tempfile::tempdir().expect("dir");
	let store = store_with(dir.path(), hash_at(DEFAULT)).into_shared();
	let before = store.credential_fingerprint("alice").expect("digest");
	cost::scoped(STRONGER, || login(&store, fixtures::password())).expect("signed in");
	assert_eq!(writes(store.store_path()), 1);
	assert_eq!(store.credential_fingerprint("alice"), Some(before.clone()));

	let higher = Argon2Cost {
		memory_kib: 40_000,
		iterations: 4,
		parallelism: 2,
	};
	cost::scoped(higher, || login(&store, fixtures::password())).expect("signed in");
	assert_eq!(writes(store.store_path()), 2);
	assert_eq!(store.credential_fingerprint("alice"), Some(before.clone()));
	// A restart reads the same digest from the file.
	assert_eq!(
		open(dir.path()).credential_fingerprint("alice"),
		Some(before)
	);
}

#[test]
fn a_password_change_after_a_rewrite_changes_the_digest() {
	let dir = tempfile::tempdir().expect("dir");
	let store = rewritten(dir.path(), STRONGER);
	let kept = store.credential_fingerprint("alice").expect("digest");
	let same_cost = hash_at(STRONGER);
	store
		.set_password_hash("alice", same_cost, None)
		.expect("change");
	assert_ne!(store.credential_fingerprint("alice"), Some(kept));
	assert!(persisted(dir.path()).rehashed.is_none());
}

#[test]
fn a_marker_made_for_another_hash_is_ignored() {
	let dir = tempfile::tempdir().expect("dir");
	let store = rewritten(dir.path(), STRONGER);
	let kept = store.credential_fingerprint("alice").expect("digest");
	let mut account = persisted(dir.path());
	account.password_hash =
		hash_password_with_cost(fixtures::second_password(), DEFAULT, &[4; 16]).expect("hash");
	assert_ne!(
		crate::directory_store::password_rehash::fingerprint(&account),
		kept
	);
}

#[test]
fn a_second_factor_change_after_a_rewrite_changes_the_digest() {
	let dir = tempfile::tempdir().expect("dir");
	let store = rewritten(dir.path(), STRONGER);
	let kept = store.credential_fingerprint("alice").expect("digest");
	let mut account = persisted(dir.path());
	account.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
	assert_ne!(
		crate::directory_store::password_rehash::fingerprint(&account),
		kept
	);
}
