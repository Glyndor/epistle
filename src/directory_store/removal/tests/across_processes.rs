//! The CLI and the server are separate processes on one data directory: a
//! removal running in one refuses the same removal in the other, and one
//! whose process died can be run again.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::antispam::bans::{BanInfo, BanStore};
use crate::directory_store::removal::{QueuePolicy, remove_account};
use crate::directory_store::{AccountStore, StoreError};
use crate::storage::FsSpool;

use super::base::*;

type Wait<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The variable that turns the test below, run again in a child process,
/// into the process whose removal is under way.
const HOLDER: &str = "EPISTLE_TEST_REMOVAL_HOLDER";

/// Written by the child once its removal is at its first wait.
const UNDER_WAY: &str = "removal-under-way";

/// The longest either process waits for the other.
const LIMIT: Duration = Duration::from_secs(60);

/// A ban store that says the removal has reached it and never answers, so
/// the removal stays where it is until its process is killed.
#[derive(Debug)]
struct Stuck(PathBuf);

impl BanStore for Stuck {
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
			std::fs::write(&self.0, b"").expect("say so");
			tokio::time::sleep(LIMIT).await;
			// Nobody killed this process: end it rather than finish.
			std::process::exit(1);
		})
	}
}

/// The child process, killed when dropped so a failed assertion leaves none.
struct Holder(Child);

impl Drop for Holder {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

fn open(dir: &Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec![DOMAIN.to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
}

async fn hold(dir: &Path) {
	let store = open(dir).with_ban_store(Arc::new(Stuck(dir.join(UNDER_WAY))));
	let spool = FsSpool::open(dir).expect("open spool");
	let ended = remove_account(&store, &spool, dir, "alice", QueuePolicy::Drain, None).await;
	panic!("the held removal ended: {ended:?}");
}

fn start_holder(dir: &Path) -> Holder {
	let child = Command::new(std::env::current_exe().expect("test binary"))
		.args([
			"--exact",
			"directory_store::removal::tests::across_processes::a_removal_in_another_process_is_not_run_over",
			"--test-threads=1",
		])
		.env(HOLDER, dir)
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.expect("run the holder");
	let mut holder = Holder(child);
	let started = Instant::now();
	while !dir.join(UNDER_WAY).exists() {
		let ended = holder.0.try_wait().expect("poll the holder");
		assert!(ended.is_none(), "the holder ended early: {ended:?}");
		assert!(started.elapsed() < LIMIT, "the holder never started");
		std::thread::sleep(Duration::from_millis(20));
	}
	holder
}

#[tokio::test]
async fn a_removal_in_another_process_is_not_run_over() {
	if let Ok(dir) = std::env::var(HOLDER) {
		hold(Path::new(&dir)).await;
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	add_account(&store, "alice", "alice@example.org");
	add_account(&store, "bob", "bob@example.org");
	let holder = start_holder(dir.path());
	// A message the holder has already walked past: only a second removal
	// would discard it.
	enqueue(&spool, "alice@example.org", Some("alice"), "late");
	let accounts = dir.path().join("accounts.toml");
	let held = std::fs::read_to_string(&accounts).expect("accounts");
	assert!(held.contains("[removals]"), "{held}");

	let second = remove_account(
		&open(dir.path()),
		&spool,
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
	assert_eq!(spool.list().expect("list").len(), 1, "nothing was touched");
	assert_eq!(
		std::fs::read_to_string(&accounts).expect("accounts"),
		held,
		"the reservation is still the holder's"
	);
	// Only the account being removed is held.
	remove_account(
		&open(dir.path()),
		&spool,
		dir.path(),
		"bob",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("another account is free");

	// The process dies half way: its reservation stays in the file, and
	// running the removal again takes it over.
	drop(holder);
	let left = std::fs::read_to_string(&accounts).expect("accounts");
	assert!(left.contains("[removals]"), "{left}");
	let store = open(dir.path());
	remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Discard,
		None,
	)
	.await
	.expect("run again");
	assert!(store.dynamic("alice").is_none());
	assert!(spool.list().expect("list").is_empty());
	let after = std::fs::read_to_string(&accounts).expect("accounts");
	assert!(!after.contains("[removals]"), "{after}");
}
