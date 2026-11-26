//! A removal reserves the account before it destroys anything: a caller that
//! may no longer remove it is refused with everything in place, no other write
//! moves or removes the account while the removal runs, and a removal that
//! stops half way can be run again.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::antispam::bans::{BanInfo, BanStore};
use crate::directory_store::removal::{QueuePolicy, remove_account, remove_account_if};
use crate::directory_store::{AccountStore, StoreError};
use crate::storage::FsSpool;

use super::base::*;

type Wait<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A ban store that holds a removal at its first wait, after the account is
/// reserved and its satellites are being cleared.
#[derive(Debug, Default)]
struct Gate {
	entered: tokio::sync::Notify,
	release: tokio::sync::Notify,
}

impl BanStore for Gate {
	fn record_failure(&self, _: &str, _: &str, _: u64) -> Wait<'_, ()> {
		Box::pin(async {})
	}

	fn is_banned(&self, _: &str, _: u64) -> Wait<'_, Option<BanInfo>> {
		Box::pin(async { None })
	}

	fn clear_success(&self, _: &str, _: u64) -> Wait<'_, ()> {
		Box::pin(async {})
	}

	fn sweep(&self, _: u64) -> Wait<'_, ()> {
		Box::pin(async {})
	}

	fn remove_account(&self, _: &str) -> Wait<'_, ()> {
		Box::pin(async move {
			self.entered.notify_one();
			self.release.notified().await;
		})
	}
}

fn gated(dir: &std::path::Path) -> (Arc<AccountStore>, FsSpool, Arc<Gate>) {
	let gate = Arc::new(Gate::default());
	let store = Arc::new(
		AccountStore::open(
			dir,
			vec![DOMAIN.to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store")
		.with_ban_store(gate.clone()),
	);
	let spool = FsSpool::open(dir).expect("open spool");
	(store, spool, gate)
}

#[tokio::test]
async fn reservation_refused_leaves_everything_in_place() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");
	let refused = remove_account_if(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Discard,
		None,
		|_| false,
	)
	.await;
	assert!(
		matches!(refused, Err(StoreError::NotFound(_))),
		"{refused:?}"
	);
	assert_eq!(spool.list().expect("list").len(), 3, "the queue is whole");
	assert!(dir.path().join("accounts/alice").exists());
	assert_eq!(store.remove_all_masked("alice").expect("masks"), 1);
	// Nothing holds the account: it takes writes as before.
	store.set_disabled("alice", true).expect("still writable");
}

#[tokio::test]
async fn reservation_holds_the_account_while_the_removal_runs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool, gate) = gated(dir.path());
	add_account(&store, "alice", "alice@example.org");
	add_account(&store, "bob", "bob@example.org");
	let removal = {
		let store = Arc::clone(&store);
		let data = dir.path().to_path_buf();
		tokio::spawn(async move {
			let spool = FsSpool::open(&data).expect("open spool");
			remove_account(&store, &spool, &data, "alice", QueuePolicy::Drain, None).await
		})
	};
	gate.entered.notified().await;
	let mut moved = store.dynamic_account("alice").expect("alice");
	moved.addresses = vec!["elsewhere@example.org".to_string()];
	for refused in [
		store.replace_account("alice", moved, None),
		store.remove("alice"),
	] {
		assert!(
			matches!(refused, Err(StoreError::BeingRemoved(_))),
			"{refused:?}"
		);
	}
	// A second removal does not run over the first.
	let spool_again = FsSpool::open(dir.path()).expect("open spool");
	let second = remove_account(
		&store,
		&spool_again,
		dir.path(),
		"alice",
		QueuePolicy::Discard,
		None,
	)
	.await;
	assert!(
		matches!(second, Err(StoreError::BeingRemoved(_))),
		"{second:?}"
	);
	// What takes access away is still taken.
	store.set_disabled("alice", true).expect("suspended");
	store
		.set_password_hash("alice", "$argon2id$late".to_string(), None)
		.expect("password replaced");
	// Another account is not held.
	store.set_disabled("bob", true).expect("bob is free");
	gate.release.notify_one();
	removal.await.expect("task").expect("removed");
	assert!(store.dynamic("alice").is_none());
	// The name is free again, with nothing left over.
	add_account(&store, "alice", "alice@example.org");
	store.set_disabled("alice", true).expect("a new account");
	drop(spool);
}

#[tokio::test]
async fn reservation_of_a_removal_that_stopped_is_taken_over() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	add_account(&store, "alice", "alice@example.org");
	// The keys are revoked near the end: a directory where their file should
	// be stops the removal there.
	std::fs::create_dir(dir.path().join("api_keys.toml")).expect("in the way");
	let failed = remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		None,
	)
	.await;
	assert!(matches!(failed, Err(StoreError::Io(_))), "{failed:?}");
	assert!(matches!(
		store.remove("alice"),
		Err(StoreError::BeingRemoved(_))
	));
	store.set_disabled("alice", true).expect("suspended");
	std::fs::remove_dir(dir.path().join("api_keys.toml")).expect("out of the way");
	remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("run again");
	assert!(store.dynamic("alice").is_none());
}
