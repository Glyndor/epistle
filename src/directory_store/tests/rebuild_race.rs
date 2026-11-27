//! A directory built before another one must never replace it.
//!
//! Every change to the store rebuilds the directory and swaps it into the
//! hot handle. Without a lock around the build and the swap, two threads
//! can build in one order and swap in the other: the older directory wins,
//! and an account the server just suspended is active again.
//!
//! The test holds a rebuild between its build and its swap — the pause the
//! store keeps for the tests alone — and suspends the account from another
//! thread. The suspension lands while the rebuild waits, so the directory
//! that stays in memory is the one built last: the one that saw the
//! suspension.

use std::sync::Arc;

use super::base::*;

/// The pause the test puts between a rebuild's build and its swap.
///
/// The first rebuild that reaches it stops there until the test lets it
/// go; the ones after it go straight through.
struct Pause {
	armed: std::sync::atomic::AtomicBool,
	/// The permit that tells the test a rebuild reached the pause.
	reached: tokio::sync::Semaphore,
	/// The flag the test flips to let the paused rebuild swap.
	release: std::sync::Mutex<bool>,
	condvar: std::sync::Condvar,
}

impl Pause {
	/// A pause that is armed: the next rebuild stops in it.
	fn new() -> Arc<Self> {
		Arc::new(Self {
			armed: std::sync::atomic::AtomicBool::new(true),
			reached: tokio::sync::Semaphore::new(0),
			release: std::sync::Mutex::new(false),
			condvar: std::sync::Condvar::new(),
		})
	}

	/// The hook the store calls between the build and the swap.
	fn hook(pause: &Arc<Self>) -> Arc<dyn Fn() + Send + Sync> {
		let pause = Arc::clone(pause);
		Arc::new(move || {
			if !pause.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
				return;
			}
			pause.reached.add_permits(1);
			let mut released = pause.release.lock().expect("pause lock");
			while !*released {
				released = pause.condvar.wait(released).expect("pause wait");
			}
		})
	}

	/// Let the paused rebuild swap the directory it built.
	fn release(&self) {
		let mut released = self.release.lock().expect("pause lock");
		*released = true;
		self.condvar.notify_all();
	}
}

/// The scenario the store has to survive: a rebuild that started before
/// the suspension must not put its older directory back into the handle
/// once the suspension has landed.
///
/// The rebuild waits in the pause while the suspension writes its file and
/// reaches its own rebuild. With the store's directory lock, that rebuild
/// waits for the paused one, so the directory that ends up in the handle
/// is the one built last: the one that saw the suspension. Without the
/// lock, the two interleave and the older directory wins.
#[tokio::test]
async fn a_rebuild_that_started_earlier_cannot_resurrect_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	store.add(dynamic("bob", "bob@example.org")).expect("add");

	let pause = Pause::new();
	store.set_build_pause(Some(Pause::hook(&pause)));

	// The first rebuild stops between its build and its swap, with a
	// directory that does not know about the suspension yet. This write
	// does not take the accounts file lock, so the only lock the paused
	// rebuild holds is the store's directory lock: the suspension can
	// write its file and reach its rebuild while the pause lasts.
	let rebuilder = {
		let store = Arc::clone(&store);
		std::thread::spawn(move || store.set_sql_accounts(Vec::new()))
	};
	// Wait for the rebuild to reach the pause.
	tokio::time::timeout(std::time::Duration::from_secs(60), pause.reached.acquire())
		.await
		.expect("the rebuild reached the pause")
		.expect("the pause is open")
		.forget();

	// Another thread suspends the account: it writes the file, replaces
	// the mirror and rebuilds.
	let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
	let suspender = {
		let store = Arc::clone(&store);
		std::thread::spawn(move || {
			let _ = store.set_disabled("bob", true);
			let _ = done_tx.send(());
		})
	};

	// The suspension either waits for the directory lock — the lock is
	// there — or finishes on its own, which is the bug: the two
	// interleave and the older directory wins.
	let events = store.directory_events();
	tokio::select! {
		permit = events.acquire() => {
			permit.expect("open").forget();
		}
		result = done_rx.recv() => {
			result.expect("the suspender thread ended without a result");
		}
	}

	// Let the paused rebuild swap the directory it built before the
	// suspension.
	pause.release();
	rebuilder.join().expect("join");
	suspender.join().expect("join");

	// The directory that stays in memory is the one built last.
	let directory = store.handle().current();
	assert!(
		directory.is_disabled("bob"),
		"a directory built before the suspension must not replace the one built after it"
	);
}
