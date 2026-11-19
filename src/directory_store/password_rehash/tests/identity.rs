//! A rewrite of the hash is not a change of the password: a grant bound to
//! the credentials keeps working, any real change still ends it, a pending
//! reset of credentials never slips, and a password change that races the
//! rewrite is never undone.

use super::*;
use crate::directory_store::ResetTarget;
use crate::directory_store::credential_reset::hash_digest;
use crate::smtp::auth::{cost, verify_password};

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

#[test]
fn a_reset_decided_before_the_rewrite_still_lands_and_the_old_password_stops() {
	let dir = tempfile::tempdir().expect("dir");
	let old = hash_at(DEFAULT);
	let store = store_with(dir.path(), old.clone()).into_shared();
	let target = ResetTarget {
		name: "alice".to_string(),
		digest: hash_digest(&old),
	};
	cost::scoped(STRONGER, || login(&store, fixtures::password())).expect("signed in");
	assert_eq!(writes(store.store_path()), 1);
	let rewritten = persisted(dir.path());
	assert_ne!(rewritten.password_hash, old);
	assert!(
		rewritten.holds_hash_digest(&target.digest),
		"not landed yet"
	);

	let placeholder =
		hash_password_with_cost("never-known-by-anyone", DEFAULT, &[8; 16]).expect("placeholder");
	let reset = store
		.reset_credentials(std::slice::from_ref(&target), &placeholder)
		.expect("reset");
	assert_eq!(reset, vec!["alice".to_string()]);
	let after = persisted(dir.path());
	assert!(after.reset.is_some());
	assert!(!after.holds_hash_digest(&target.digest), "landed");
	assert_eq!(login(&store, fixtures::password()), None);
}

#[test]
fn a_digest_that_names_another_hash_does_not_match_a_rewritten_account() {
	let dir = tempfile::tempdir().expect("dir");
	let store = store_with(dir.path(), hash_at(DEFAULT)).into_shared();
	cost::scoped(STRONGER, || login(&store, fixtures::password())).expect("signed in");
	assert!(!persisted(dir.path()).holds_hash_digest(&hash_digest(&hash_at(STRONGER))));
}

#[test]
fn a_password_change_racing_a_rewrite_always_wins() {
	for round in 0..3u8 {
		let dir = tempfile::tempdir().expect("dir");
		let old = hash_at(DEFAULT);
		let store = store_with(dir.path(), old.clone()).into_shared();
		let changed = hash_password_with_cost(fixtures::second_password(), DEFAULT, &[round; 16])
			.expect("hash");
		let barrier = std::sync::Barrier::new(2);
		std::thread::scope(|scope| {
			scope.spawn(|| {
				barrier.wait();
				cost::scoped(STRONGER, || {
					store.rehash_password("alice", &old, fixtures::password());
				});
			});
			scope.spawn(|| {
				barrier.wait();
				store
					.set_password_hash("alice", changed.clone(), None)
					.expect("change");
			});
		});
		let stored = persisted(dir.path()).password_hash;
		assert!(
			verify_password(&stored, fixtures::second_password()),
			"round {round}"
		);
		assert!(
			!verify_password(&stored, fixtures::password()),
			"round {round}"
		);
	}
}
