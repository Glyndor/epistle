//! A reload must never put a state back into memory that is older than
//! the one the server just wrote.
//!
//! The file watcher reads a dynamic-store file and swaps the in-memory
//! mirror with it. Without a lock shared with the writers, a write that
//! lands between the read and the swap is undone by the swap: an account
//! the server just suspended is active again. The reload therefore reads
//! and swaps under the same lock the mutators take, so the newest state
//! wins whichever order the two arrive in.

use std::sync::Arc;

use super::base::*;

/// The file as the mutator leaves it: the account is suspended.
const SUSPENDED: &str = r#"
[[accounts]]
name = "bob"
addresses = ["bob@example.org"]
password_hash = "$argon2id$stub"
disabled = true
"#;

/// Wait for one permit of `counter`: an event that has to happen. The
/// limit is only there so that a lost signal fails the test and does not
/// hang it.
async fn wait_for(counter: &tokio::sync::Semaphore, what: &str) {
	tokio::time::timeout(std::time::Duration::from_secs(60), counter.acquire())
		.await
		.unwrap_or_else(|_| panic!("never happened: {what}"))
		.expect("open")
		.forget();
}

/// The scenario the watcher can hit: it read the file, the server
/// suspended the account (writing the file and replacing the mirror),
/// and the watcher's read landed after that write. The account stays
/// suspended: the reload re-reads the file under the writers' lock, so
/// it cannot carry the older state back into memory.
#[test]
fn a_reload_after_a_suspension_does_not_resurrect_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let path = dir.path().join("accounts.toml");
	// The text the watcher read before the mutator wrote.
	let stale = std::fs::read_to_string(&path).expect("read accounts.toml");

	// The mutator suspends the account: it writes the file and replaces
	// the mirror.
	store.set_disabled("bob", true).expect("suspend");
	assert!(store.is_disabled("bob"), "the mutator suspends the account");
	assert_ne!(
		stale,
		std::fs::read_to_string(&path).expect("read accounts.toml"),
		"the mutator's write moved the file under the watcher"
	);

	// The watcher's reload lands.
	store.reload_accounts().expect("reload");
	assert!(
		store.is_disabled("bob"),
		"a reload must not put a state back into memory that is older than the last write"
	);
}

/// The reload takes the same lock the writers take, so it cannot read
/// the file while a write is in flight. The test holds that lock and
/// watches the reload ask for it: the reload waits, and the mirror only
/// moves once the lock is free.
#[tokio::test]
async fn a_reload_waits_for_the_writers_lock() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let path = dir.path().join("accounts.toml");
	// The file says the account is suspended; the mirror still says
	// otherwise, because the reload has not run yet.
	crate::storage::write_secret(&path, SUSPENDED.as_bytes()).expect("write accounts.toml");

	let lock = crate::storage::locked::lock_path(&path);
	let held = crate::storage::lock::FileLock::acquire(&lock).expect("lock");
	let reached = crate::storage::lock::reached::watch(&lock);
	let worker = {
		let store = Arc::clone(&store);
		std::thread::spawn(move || store.reload_accounts())
	};
	wait_for(&reached, "the reload asks for the writers' lock").await;
	assert!(
		!store.is_disabled("bob"),
		"the reload must not swap the mirror while the writers' lock is held"
	);

	drop(held);
	worker.join().expect("join").expect("reload");
	assert!(
		store.is_disabled("bob"),
		"the reload swaps the mirror once the writers' lock is free"
	);
}

/// The masked writers hold the mirror's lock and take the file's lock
/// inside it, so the reload takes them in the same order. The test
/// runs a reload and a write against each other with the file's lock
/// held: the reload waits for the mirror, the write waits for the
/// mirror too, and neither of them waits for the other.
#[tokio::test]
async fn a_masked_reload_does_not_wait_for_a_masked_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	let entry = store
		.add_masked("bob", "shop", "example.org", 1)
		.expect("add masked");
	let path = dir.path().join("masked.json");
	let lock = crate::storage::locked::lock_path(&path);
	let held = crate::storage::lock::FileLock::acquire(&lock).expect("lock");
	let reached = crate::storage::lock::reached::watch(&lock);

	// The reload goes first: it takes the mirror's lock and then asks
	// for the file's. The write that follows waits for the mirror.
	let (done_tx, done_rx) = std::sync::mpsc::channel();
	let reloader = {
		let store = Arc::clone(&store);
		let done = done_tx.clone();
		std::thread::spawn(move || {
			let _ = store.reload_masked();
			let _ = done.send("the reload");
		})
	};
	wait_for(&reached, "the reload asks for the file's lock").await;
	let writer = {
		let store = Arc::clone(&store);
		let address = entry.address.clone();
		let done = done_tx.clone();
		std::thread::spawn(move || {
			let _ = store.set_masked_enabled("bob", &address, false);
			let _ = done.send("the write");
		})
	};

	// The file's lock is free: the reload takes it, reads the file and
	// waits for the mirror, which the write holds. The write waits for
	// the file's lock, which the reload holds. The two must not wait
	// for each other, so both finish.
	drop(held);
	for what in ["the reload", "the write"] {
		assert!(
			done_rx
				.recv_timeout(std::time::Duration::from_secs(60))
				.is_ok(),
			"{what} never finished: the reload and the write wait for each other"
		);
	}
	reloader.join().expect("join");
	writer.join().expect("join");

	let handle = store.masked_handle();
	let mirror = handle.read().expect("masked lock");
	assert!(
		!mirror.get(&entry.address).expect("entry").enabled,
		"the write's disabled mask survives the reload"
	);
}
