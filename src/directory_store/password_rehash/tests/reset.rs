//! A rewrite of the hash never lets a pending reset of credentials slip, and
//! never undoes a password change that races it.

use super::*;
use crate::directory_store::ResetTarget;
use crate::directory_store::credential_reset::hash_digest;
use crate::smtp::auth::{cost, verify_password};

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
