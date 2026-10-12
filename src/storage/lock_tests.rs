//! `flock`-based cross-process advisory locks.
//!
//! The unit tests under this module prove the primitive blocks a
//! second holder through the kernel's per-open-file-description
//! semantics. The end-to-end "two store handles survive each other"
//! tests live with their owning store because they exercise the
//! store's mutation API.
//!
//! Same-process flock semantics (Linux): two `open(2)` calls on the
//! same path give two distinct open file descriptions and contend;
//! duplicate file descriptors (from `dup(2)` or `fork(2)`) share a
//! single lock. The tests that need "another holder" therefore open
//! the lock file twice (one per thread) rather than `try_clone()`-ing
//! it.

use std::os::fd::AsRawFd;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::lock::{FileLock, flock_exclusive_blocking, flock_exclusive_nonblocking, open_lock_file};

/// `try_acquire` on a free path hands back the lock; dropping the guard
/// frees it for the next caller.
#[test]
fn try_acquire_returns_some_when_no_holder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join(".test.lock");
	let lock = FileLock::try_acquire(&path).expect("io ok");
	let lock = lock.expect("free path is acquirable");
	drop(lock);
	// A second acquire after release is allowed.
	let again = FileLock::try_acquire(&path)
		.expect("io ok")
		.expect("reacquired");
	drop(again);
}

/// A second `try_acquire` while a holder keeps an exclusive lock on a
/// different open file description of the same path returns `Ok(None)`
/// (the kernel associates `flock(2)` with the open file description;
/// two descriptions on the same path made from separate `open(2)` calls
/// contend for the lock within one process).
#[test]
fn try_acquire_returns_none_while_held_on_a_distinct_ofd() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join(".test.lock");

	// The holder thread owns its `File` so the lock releases when the
	// thread unwinds (closing the FD releases the `flock`).
	let (ready_tx, ready_rx) = mpsc::channel::<()>();
	let (release_tx, release_rx) = mpsc::channel::<()>();
	let path_for_holder = path.clone();
	let holder = thread::spawn(move || {
		let holder_file = open_lock_file(&path_for_holder).expect("open in holder");
		flock_exclusive_blocking(holder_file.as_raw_fd()).expect("holder flock");
		ready_tx.send(()).expect("ready");
		release_rx.recv().expect("release");
		// `holder_file` drops on closure exit, releasing the flock.
	});
	ready_rx.recv().expect("wait for ready");

	// Main thread opens the same path under a fresh OFD and tries to
	// take the lock without blocking: the kernel has already granted
	// an exclusive flock on the path, so this attempt must fail with
	// `EWOULDBLOCK`.
	let main_file = open_lock_file(&path).expect("open in main");
	let result = flock_exclusive_nonblocking(main_file.as_raw_fd());
	match result {
		Ok(()) => panic!("flock acquired while another OFD held the exclusive lock"),
		Err(error) if error.raw_os_error() == Some(libc::EWOULDBLOCK) => {}
		Err(other) => panic!("unexpected flock error: {other}"),
	}

	release_tx.send(()).expect("signal release");
	holder.join().expect("holder thread");

	// `holder_file` is gone now (closed by the thread dropping it), so
	// the flock is released; main's OFD can take the lock.
	flock_exclusive_nonblocking(main_file.as_raw_fd()).expect("flock after release");
}

/// `FileLock::try_acquire` walks the same path as the syscall below it:
/// reports `None` while another lock (here, on a distinct OFD of the
/// same path) holds the exclusive `flock`, and `Some` once the holder
/// has dropped.
#[test]
fn try_acquire_filelock_walks_the_nonblocking_flop() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join(".test.lock");
	let holder = FileLock::acquire(&path).expect("holder file lock");

	let attempt = FileLock::try_acquire(&path).expect("io ok");
	assert!(
		attempt.is_none(),
		"try_acquire on a path another FileLock owns within this process must yield None"
	);

	drop(holder);

	let after = FileLock::try_acquire(&path)
		.expect("io ok")
		.expect("free after release");
	drop(after);
}

/// The blocking `acquire` parks until the holder drops. The test sets
/// a generous upper bound on the wait so a regression that never wakes
/// up surfaces as a hang instead of a silent false-pass.
#[test]
fn acquire_blocks_until_holder_releases() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join(".test.lock");
	let holder = FileLock::acquire(&path).expect("holder file lock");

	let path_for_waiter = path.clone();
	let (done_tx, done_rx) = mpsc::channel::<()>();
	let waiter = thread::spawn(move || {
		let _guard = FileLock::acquire(&path_for_waiter).expect("acquired after release");
		done_tx.send(()).expect("done");
	});
	// Give the waiter a moment to park on `flock`. If it does not
	// block (a regression that turns `LOCK_EX` into a no-op), the
	// channel receives immediately and the assertion below catches it.
	thread::sleep(Duration::from_millis(50));
	assert!(
		done_rx.try_recv().is_err(),
		"the waiter must still be parked while the holder owns the lock"
	);

	drop(holder);
	done_rx
		.recv_timeout(Duration::from_secs(2))
		.expect("waiter should acquire within 2s after release");
	waiter.join().expect("waiter thread");
}
