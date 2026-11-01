//! A stop signal reaches the command and does not end the process waiting
//! for it (#1342).

use super::*;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The relay is process-wide state, so the tests that use it take turns.
static TURN: Mutex<()> = Mutex::new(());

fn shell(script: &str) -> Command {
	let mut command = Command::new("sh");
	command.arg("-c").arg(script);
	command
}

/// Wait, with a bound, until `path` exists.
fn exists_within(path: &Path, limit: Duration) -> bool {
	let deadline = Instant::now() + limit;
	while Instant::now() < deadline {
		if path.exists() {
			return true;
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	false
}

#[test]
fn a_command_that_needs_longer_than_runuser_allowed_finishes_cleanly() {
	let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
	let dir = tempfile::tempdir().unwrap();
	let (ready, clean) = (dir.path().join("ready"), dir.path().join("clean"));
	// Like a restore that holds the stop signals: on SIGTERM it takes three
	// seconds to close, longer than the two after which `runuser` killed it.
	let mut command = shell(&format!(
		"trap 'sleep 3; echo clean > {clean}; exit 0' TERM; echo up > {ready}; \
		 while :; do sleep 0.1; done",
		clean = clean.display(),
		ready = ready.display(),
	));
	let waiting = std::thread::spawn(move || {
		let started = Instant::now();
		(run(&mut command), started)
	});
	assert!(
		exists_within(&ready, Duration::from_secs(10)),
		"the command never started"
	);
	// A process-wide signal, as one aimed at the group reaches this process.
	// Without the relay it ends the test process by the default action.
	// SAFETY: kill sends a signal to this very process.
	unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
	let (status, started) = waiting.join().unwrap();
	let status = status.unwrap();
	assert!(
		status.success(),
		"the command was ended instead of finishing: {status:?}"
	);
	assert!(clean.exists(), "the command did not reach its clean finish");
	assert!(
		started.elapsed() >= Duration::from_secs(3),
		"the command was not given the time it asked for"
	);
}

#[test]
fn a_signal_that_came_while_the_command_started_is_passed_on() {
	let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
	let relay_guard = Relay::install().expect("no other relay is alive");
	// The handler runs before there is a command to pass it to.
	relay(libc::SIGTERM);
	let mut command = shell("sleep 30");
	let mut child = command.spawn().unwrap();
	relay_guard.attach(child.id() as libc::pid_t);
	let status = child.wait().unwrap();
	assert_eq!(
		status.signal(),
		Some(libc::SIGTERM),
		"the early signal must reach the command: {status:?}"
	);
}

#[test]
fn the_handlers_are_put_back_when_the_command_ends() {
	let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
	let before = disposition(libc::SIGTERM);
	let status = run(&mut shell("exit 3")).unwrap();
	assert_eq!(status.code(), Some(3));
	assert_eq!(disposition(libc::SIGTERM), before);
	assert!(
		Relay::install().is_some(),
		"a finished run must release its hold"
	);
}

fn disposition(signal: libc::c_int) -> libc::sighandler_t {
	// SAFETY: a zeroed sigaction is valid storage for the query.
	let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
	// SAFETY: reads the current disposition into `action`.
	unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) };
	action.sa_sigaction
}

#[test]
fn an_exit_code_is_the_commands_own_or_128_plus_its_signal() {
	let finished = |script: &str| shell(script).status().unwrap();
	assert_eq!(exit_code(finished("exit 7")), 7);
	assert_eq!(exit_code(finished("exit 0")), 0);
	assert_eq!(
		exit_code(finished("kill -TERM $$")),
		128 + libc::SIGTERM as u8,
		"a command ended by a signal reports it the way a shell does"
	);
}
