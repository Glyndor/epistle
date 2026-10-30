//! The generated file's lock: a holder in another process must not keep a
//! command waiting longer than the deadline the common lock uses.

use crate::cli::compose::lock::tests::*;

use std::path::Path;
use std::time::Duration;

/// The variable that turns this test, run again in a child process, into the
/// process that holds the lock. The holder is another process on purpose: that
/// is what a writer of the file waits for, and what the kernel serialises it
/// against.
const HOLDER: &str = "EPISTLE_TEST_COMPOSE_LOCK_HOLDER";

#[test]
fn a_holder_in_another_process_ends_the_wait_at_its_deadline() {
	if let Ok(lock) = std::env::var(HOLDER) {
		hold(&lock);
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let lock = dir.path().join(".compose.yaml.lock");
	let mut holder = std::process::Command::new(std::env::current_exe().expect("test binary"))
		.args([
			"--exact",
			"cli::compose::lock::tests::base::a_holder_in_another_process_ends_the_wait_at_its_deadline",
			"--test-threads=1",
		])
		.env(HOLDER, &lock)
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::null())
		.spawn()
		.expect("run the holder");
	wait_for_holder(&lock, &mut holder);
	// The waiting acquisition runs in a thread of its own, so a lock taken
	// without a deadline is a failed assertion here and not a hung test.
	let (done, waited) = std::sync::mpsc::channel();
	let waiting = lock.clone();
	std::thread::spawn(move || {
		done.send(acquire_within(&waiting, Duration::from_millis(300)))
			.unwrap();
	});
	let error = match waited
		.recv_timeout(Duration::from_secs(10))
		.expect("the wait must end at its deadline instead of waiting forever")
	{
		Err(error) => error,
		Ok(_) => panic!("a lock held elsewhere must not be taken"),
	};
	assert!(
		error.contains(&lock.display().to_string()) && error.contains("retry once it has finished"),
		"the refusal must name the lock file and what to do: {error}"
	);
	holder.kill().expect("stop the holder");
	holder.wait().expect("reap the holder");
	assert!(
		acquire_within(&lock, Duration::from_secs(5)).is_ok(),
		"the lock is free again once the holder is gone"
	);
}

/// Take the lock in this child and keep it until the parent kills this
/// process, which is what releases it.
fn hold(lock: &str) {
	let _held = FileLock::acquire(Path::new(lock)).expect("take the compose lock");
	loop {
		std::thread::sleep(Duration::from_millis(50));
	}
}

/// Wait until the child holds the lock, so the refusal above is about a lock
/// that is really taken and not about one the child has not reached yet.
fn wait_for_holder(lock: &Path, holder: &mut std::process::Child) {
	let deadline = Instant::now() + Duration::from_secs(10);
	while Instant::now() < deadline {
		match FileLock::try_acquire(lock).expect("open the lock") {
			Some(taken) => drop(taken),
			None => return,
		}
		std::thread::sleep(Duration::from_millis(50));
	}
	let _ = holder.kill();
	panic!("the holder never took {}", lock.display());
}

/// The common lock and this one spend one budget, not one each. A command that
/// queued for the common lock until 300 ms of its 30 s were left waits 300 ms
/// for this one, so the two holders together cannot keep it out for a minute.
#[test]
fn the_wait_is_what_the_common_lock_left_of_the_budget() {
	let dir = tempfile::tempdir().unwrap();
	let lock = dir.path().join(".compose.yaml.lock");
	let held = FileLock::try_acquire(&lock).unwrap().expect("a free lock");
	let (done, waited) = std::sync::mpsc::channel();
	let waiting = lock.clone();
	// The budget is per thread, so the clock starts on the thread that waits.
	std::thread::spawn(move || {
		let began = std::time::Instant::now();
		crate::cli::service::lock::began_at(
			began - (crate::cli::service::lock::WAIT - Duration::from_millis(300)),
		);
		let outcome = acquire(&waiting);
		done.send((outcome.is_err(), began.elapsed())).unwrap();
	});
	let (refused, took) = waited
		.recv_timeout(Duration::from_secs(10))
		.expect("the wait must end with the budget of the common lock, not a fresh 30 s");
	assert!(refused, "a lock held elsewhere must not be taken");
	assert!(took < Duration::from_secs(5), "waited {took:?}");
	drop(held);
}
