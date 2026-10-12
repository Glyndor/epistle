//! The in-memory mirror of `accounts.toml` is refreshed while the
//! cross-process `flock` is still held.
//!
//! `AccountStore` mutators take `&self`, so two threads of the server
//! can mutate at once. If the lock were released before the mirror is
//! replaced, a second writer could commit and refresh in between, and
//! the first writer's late refresh would roll the mirror back to the
//! older state while the disk holds the newer one.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::directory_store::{AccountStore, DynamicAccount};
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

fn account(name: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: "$argon2id$test".to_string(),
		scram: None,
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
	}
}

#[test]
fn the_flock_is_held_until_the_in_memory_mirror_is_refreshed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let accounts = dir.path().join("accounts.toml");
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![],
		)
		.expect("open store"),
	);
	// Holding a read guard on the mirror parks the writer at the step
	// that replaces it, after the file is on disk.
	let mirror = store.dynamic.read().expect("store lock");
	let writer = {
		let store = Arc::clone(&store);
		thread::spawn(move || store.add(account("alice")))
	};
	let deadline = Instant::now() + Duration::from_secs(10);
	while !std::fs::read_to_string(&accounts).is_ok_and(|text| text.contains("alice")) {
		assert!(
			Instant::now() < deadline,
			"the writer never committed alice to disk"
		);
		thread::sleep(Duration::from_millis(5));
	}
	// Leave the writer time to drop the lock if it is going to.
	thread::sleep(Duration::from_millis(200));
	let probe = FileLock::try_acquire(&lock_path(&accounts)).expect("probe the lock");
	let held_during_refresh = probe.is_none();
	drop(probe);
	drop(mirror);
	writer.join().expect("writer thread").expect("add alice");
	assert!(
		held_during_refresh,
		"the accounts.toml flock was free while the mirror was still stale: a second writer could commit in between and the late refresh would roll the mirror back"
	);
	assert!(
		store.dynamic("alice").is_some(),
		"the mirror must hold alice once the writer returns"
	);
}
