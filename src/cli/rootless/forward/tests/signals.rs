//! A stop signal reaches the command and does not end the process waiting
//! for it (#1342).
//!
//! The relay installs process-wide signal handlers, and the test binary also
//! runs the restore tests, which hold the same signals. So each scenario runs
//! in a child process of its own, in a process group of its own, and the parent
//! test sends the signals to that child and never to itself: a signal that goes
//! wrong ends the child and fails the parent, not the whole test binary.

use super::*;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::time::{Duration, Instant};

/// Set in the child: the scenario to play.
const MODE: &str = "EPISTLE_TEST_RELAY_MODE";
/// Set in the child: a directory for the notes the scenario leaves.
const DIR: &str = "EPISTLE_TEST_RELAY_DIR";

fn shell(script: &str) -> Command {
	let mut command = Command::new("sh");
	command.arg("-c").arg(script);
	command
}

fn disposition(signal: libc::c_int) -> libc::sighandler_t {
	// SAFETY: a zeroed sigaction is valid storage for the query.
	let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
	// SAFETY: reads the current disposition into `action`.
	unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) };
	action.sa_sigaction
}

/// The scenarios the parent tests start. Does nothing in an ordinary run.
#[test]
fn relay_child() {
	let Some(mode) = std::env::var_os(MODE) else {
		return;
	};
	let dir = std::path::PathBuf::from(std::env::var_os(DIR).expect("scenario directory"));
	let ok = match mode.to_str().expect("utf-8 mode") {
		"slow-stop" => {
			let (ready, clean) = (dir.join("ready"), dir.join("clean"));
			// Like a restore that holds the stop signals: on SIGTERM it takes
			// three seconds to close, longer than the two after which
			// `runuser` killed it.
			let mut command = shell(&format!(
				"trap 'sleep 3; echo clean > {clean}; exit 0' TERM; echo up > {ready}; \
				 while :; do sleep 0.1; done",
				clean = clean.display(),
				ready = ready.display(),
			));
			run(&mut command).is_ok_and(|status| status.success()) && clean.exists()
		}
		"early" => {
			let guard = Relay::install().expect("no other relay is alive");
			// The handler runs before there is a command to pass it to.
			relay(libc::SIGTERM);
			let mut child = shell("sleep 30").spawn().unwrap();
			guard.attach(child.id() as libc::pid_t);
			child.wait().unwrap().signal() == Some(libc::SIGTERM)
		}
		"restored" => {
			let before = disposition(libc::SIGTERM);
			let status = run(&mut shell("exit 3")).unwrap();
			status.code() == Some(3)
				&& disposition(libc::SIGTERM) == before
				&& Relay::install().is_some()
		}
		"reaped-last" => {
			let mut seen = None;
			let status = run_with(&mut shell("exit 5"), |pid| {
				let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
				// The state follows the command name, which ends at the last ")".
				let state = stat.rsplit(')').next().unwrap().trim().chars().next();
				seen = Some((CHILD.load(Ordering::SeqCst), state));
			})
			.unwrap();
			// Nothing may signal the pid any more, and it is not yet reaped:
			// a zombie keeps the number from being given to another process.
			status.code() == Some(5) && seen == Some((0, Some('Z')))
		}
		other => panic!("unknown scenario {other}"),
	};
	std::process::exit(if ok { 0 } else { 1 });
}

/// Start the scenario `mode` in a child process of its own group.
fn start(mode: &str, dir: &Path) -> std::process::Child {
	Command::new(std::env::current_exe().expect("test binary"))
		.args([
			"--exact",
			"cli::rootless::forward::tests::signals::relay_child",
			"--test-threads=1",
		])
		.env(MODE, mode)
		.env(DIR, dir)
		.process_group(0)
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::null())
		.spawn()
		.expect("start the scenario")
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
	let dir = tempfile::tempdir().unwrap();
	let mut child = start("slow-stop", dir.path());
	assert!(
		exists_within(&dir.path().join("ready"), Duration::from_secs(20)),
		"the command never started"
	);
	let started = Instant::now();
	// SAFETY: kill sends a signal to the group of the child just started,
	// which holds the scenario and the shell it waits for, and not this test.
	unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGTERM) };
	let status = child.wait().unwrap();
	assert!(
		status.success(),
		"the waiting process or the command was ended instead of finishing: {status:?}"
	);
	assert!(
		started.elapsed() >= Duration::from_secs(3),
		"the command was not given the time it asked for"
	);
}

#[test]
fn a_signal_that_came_while_the_command_started_is_passed_on() {
	let dir = tempfile::tempdir().unwrap();
	let status = start("early", dir.path()).wait().unwrap();
	assert!(status.success(), "{status:?}");
}

#[test]
fn the_handlers_are_put_back_when_the_command_ends() {
	let dir = tempfile::tempdir().unwrap();
	let status = start("restored", dir.path()).wait().unwrap();
	assert!(status.success(), "{status:?}");
}

#[test]
fn the_command_is_reaped_only_after_nothing_can_signal_it() {
	let dir = tempfile::tempdir().unwrap();
	let status = start("reaped-last", dir.path()).wait().unwrap();
	assert!(status.success(), "{status:?}");
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
