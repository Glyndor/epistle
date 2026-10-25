//! Tests for the process probe's reading of `/proc/<pid>/status`.

use super::owned_by;

const STATUS: &str =
	"Name:\tcatatonit\nState:\tS (sleeping)\nUid:\t990\t991\t992\t993\nGid:\t990\t990\t990\t990\n";

#[test]
fn the_real_or_effective_uid_counts() {
	assert!(owned_by(STATUS, 990), "real uid");
	assert!(owned_by(STATUS, 991), "effective uid");
	assert!(
		!owned_by(STATUS, 992),
		"the saved uid does not make it the account's"
	);
	assert!(!owned_by(STATUS, 0));
	assert!(!owned_by("Name:\tx\n", 990), "no Uid line, no match");
}

#[test]
fn this_process_is_found_under_its_own_uid() {
	// SAFETY: getuid takes no arguments and cannot fail.
	let uid = unsafe { libc::getuid() };
	let me = std::process::id().to_string();
	assert!(
		super::processes_of(uid)
			.iter()
			.any(|(pid, _)| pid.to_string() == me)
	);
}

mod wiring {
	use super::super::{manager_answers, usermod_with};
	use std::os::unix::fs::PermissionsExt;
	use std::path::Path;
	use std::process::Command;
	use std::time::Duration;

	/// A script that appends a line per call to `log`, with the locale it saw,
	/// and runs `body`.
	fn script(dir: &Path, log: &Path, body: &str) -> String {
		let path = dir.join("stub");
		std::fs::write(
			&path,
			format!(
				"#!/bin/sh\nn=$(wc -l < '{log}' 2>/dev/null || echo 0)\n\
				 echo \"$LC_ALL $*\" >> '{log}'\n{body}\n",
				log = log.display()
			),
		)
		.unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
		path.to_str().unwrap().to_string()
	}

	fn calls(log: &Path) -> Vec<String> {
		std::fs::read_to_string(log)
			.unwrap_or_default()
			.lines()
			.map(str::to_string)
			.collect()
	}

	#[test]
	fn a_held_lock_is_asked_again_in_the_c_locale() {
		let dir = tempfile::tempdir().unwrap();
		let log = dir.path().join("log");
		let stub = script(
			dir.path(),
			&log,
			"[ \"$n\" -ge 2 ] || { echo 'usermod: cannot lock /etc/subuid; try again later.' >&2; exit 10; }",
		);
		let args = vec!["--add-subuids".to_string(), "1-2".to_string()];
		assert_eq!(usermod_with(&stub, &args, Duration::ZERO), Ok(()));
		assert_eq!(
			calls(&log),
			vec!["C --add-subuids 1-2 glyndor-epistle"; 3],
			"two refusals, then the call that finds the lock free"
		);
	}

	#[test]
	fn any_other_failure_is_reported_at_once() {
		let dir = tempfile::tempdir().unwrap();
		let log = dir.path().join("log");
		let stub = script(
			dir.path(),
			&log,
			"echo \"usermod: user 'glyndor-epistle' does not exist\" >&2; exit 6",
		);
		let result = usermod_with(&stub, &[], Duration::ZERO);
		assert!(result.is_err());
		assert_eq!(calls(&log).len(), 1);
	}

	#[test]
	fn a_missing_program_is_reported_without_retrying() {
		let result = usermod_with("/nonexistent/usermod", &[], Duration::ZERO);
		assert!(result.unwrap_err().starts_with("cannot run"));
	}

	#[test]
	fn the_manager_probe_waits_until_the_bus_answers() {
		let dir = tempfile::tempdir().unwrap();
		let log = dir.path().join("log");
		let stub = script(dir.path(), &log, "[ \"$n\" -ge 2 ]");
		let probe = || Command::new(&stub);
		assert!(manager_answers(probe, 10, Duration::ZERO));
		assert_eq!(calls(&log).len(), 3);
	}

	#[test]
	fn the_manager_probe_gives_up_after_its_attempts() {
		let dir = tempfile::tempdir().unwrap();
		let log = dir.path().join("log");
		let stub = script(dir.path(), &log, "exit 1");
		assert!(!manager_answers(|| Command::new(&stub), 4, Duration::ZERO));
		assert_eq!(calls(&log).len(), 4, "bounded");
	}
}
