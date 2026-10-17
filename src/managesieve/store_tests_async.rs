//! The store is called from async tasks. Waiting for an account's lock must
//! not hold a runtime worker: with a few workers and a few accounts busy, a
//! blocked worker is a stalled listener for everyone.

use std::time::{Duration, Instant};

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_for_the_lock_does_not_stall_the_runtime() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	ScriptStore::new(&root, "alice")
		.put("seed", "keep;\r\n")
		.expect("seed");
	// Something else (another process, say) holds alice's lock for a while.
	let lock_path = root.join("alice/sieve/.lock");
	let holder = std::thread::spawn(move || {
		let _held = crate::storage::lock::FileLock::acquire(&lock_path).expect("lock");
		std::thread::sleep(Duration::from_millis(800));
	});
	tokio::time::sleep(Duration::from_millis(100)).await;
	// More callers than the runtime has workers, all for alice. Something
	// unrelated has to get a turn on time while they wait.
	let started = Instant::now();
	let tasks: Vec<_> = (0..6)
		.map(|n| {
			let root = root.clone();
			tokio::spawn(async move {
				ScriptStore::new(&root, "alice").put(&format!("s{n}"), "keep;\r\n")
			})
		})
		.collect();
	tokio::time::sleep(Duration::from_millis(50)).await;
	let waited = started.elapsed();
	assert!(
		waited < Duration::from_millis(300),
		"a 50 ms sleep took {waited:?} while alice's lock was busy"
	);
	for task in tasks {
		assert_eq!(task.await.expect("task"), Ok(()));
	}
	holder.join().expect("holder");
}
