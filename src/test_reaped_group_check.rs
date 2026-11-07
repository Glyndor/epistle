//! A child started with `GroupChild` does not survive a test that panics.

use crate::test_reaped_group::{GroupChild, bounded_loop};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use std::time::{Duration, Instant};

/// True while `pid` names a process that still runs. A zombie is gone: it only
/// waits for its parent to read the status.
fn alive(pid: &str) -> bool {
	let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
	!stat.is_empty() && !stat.contains(") Z ")
}

fn gone_within(pid: &str, limit: Duration) -> bool {
	let deadline = Instant::now() + limit;
	while alive(pid) {
		if Instant::now() >= deadline {
			return false;
		}
		std::thread::sleep(Duration::from_millis(20));
	}
	true
}

#[test]
fn a_child_and_what_it_started_do_not_outlive_a_test_that_panics() {
	let dir = tempfile::tempdir().unwrap();
	let pidfile = dir.path().join("grandchild.pid");
	let mut leader = None;
	let outcome = catch_unwind(AssertUnwindSafe(|| {
		let mut command = Command::new("sh");
		command.arg("-c").arg(format!(
			"sleep 120 & echo $! > '{}'; wait",
			pidfile.display()
		));
		let child = GroupChild::spawn(&mut command).unwrap();
		leader = Some(child.id().to_string());
		let deadline = Instant::now() + Duration::from_secs(10);
		// The shell creates the file when it opens the redirection and writes
		// the number a moment later: a file that exists can still be empty.
		let written =
			|| std::fs::read_to_string(&pidfile).is_ok_and(|text| !text.trim().is_empty());
		while !written() && Instant::now() < deadline {
			std::thread::sleep(Duration::from_millis(10));
		}
		assert!(written(), "the child never started");
		panic!("the test fails with the child running");
	}));
	assert!(outcome.is_err(), "the closure must have panicked");
	let leader = leader.expect("leader pid");
	let grandchild = std::fs::read_to_string(&pidfile).unwrap().trim().to_owned();
	assert!(
		gone_within(&leader, Duration::from_secs(5)),
		"child {leader} outlived the test"
	);
	assert!(
		gone_within(&grandchild, Duration::from_secs(5)),
		"process {grandchild} started by the child outlived the test"
	);
}

#[test]
fn a_waited_child_is_not_signalled_again_on_drop() {
	let mut command = Command::new("sh");
	command.args(["-c", "exit 4"]);
	let mut child = GroupChild::spawn(&mut command).unwrap();
	assert_eq!(child.wait().unwrap().code(), Some(4));
	child.signal_group(libc::SIGKILL);
}

#[test]
fn the_bounded_loop_is_a_valid_script_that_ends_by_itself() {
	let status = Command::new("sh")
		.args(["-n", "-c", &bounded_loop()])
		.status()
		.unwrap();
	assert!(status.success());
	assert!(bounded_loop().contains("-lt 600 ]"), "{}", bounded_loop());
}
