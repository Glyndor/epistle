//! Rewriting a password hash at a higher cost after a sign-in, through the
//! store that `serve` builds, so the rewrite has to land in `accounts.toml`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::config::Protocol;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::cost::Argon2Cost;
use crate::smtp::auth::hash_password_with_cost;
use crate::test_support::fixtures;

mod identity;
mod rewrite;

static WRITES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Called by the store each time it wrote a rewritten hash.
pub(super) fn count_write(path: &Path) {
	WRITES.lock().expect("lock").push(path.to_path_buf());
}

/// How many rewritten hashes the store at `path` has written.
fn writes(path: &Path) -> usize {
	WRITES
		.lock()
		.expect("lock")
		.iter()
		.filter(|written| written.as_path() == path)
		.count()
}

const DEFAULT: Argon2Cost = Argon2Cost {
	memory_kib: 19_456,
	iterations: 2,
	parallelism: 1,
};
const STRONGER: Argon2Cost = Argon2Cost {
	memory_kib: 32_768,
	iterations: 3,
	parallelism: 2,
};

fn hash_at(cost: Argon2Cost) -> String {
	hash_password_with_cost(fixtures::password(), cost, &[9; 16]).expect("hash")
}

fn open(dir: &Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("store open")
}

/// A store on disk holding `alice` with `hash`.
fn store_with(dir: &Path, hash: String) -> AccountStore {
	let store = open(dir);
	store
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: hash,
			..DynamicAccount::default()
		})
		.expect("add");
	store
}

/// The hash as persisted, read back through a fresh store on the same
/// directory so the assertion sees `accounts.toml`, not memory.
fn persisted(dir: &Path) -> DynamicAccount {
	open(dir).dynamic("alice").expect("alice")
}

fn parameters(hash: &str) -> String {
	hash.split('$').nth(3).expect("parameters").to_string()
}

fn login(store: &AccountStore, password: &str) -> Option<String> {
	store
		.handle()
		.current()
		.authenticate_with_ip("alice", password, None, Protocol::Imap)
}
