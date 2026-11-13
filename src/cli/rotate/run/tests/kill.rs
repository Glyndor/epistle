//! The run killed between any two of its writes, and finished by the next.
//!
//! A child process runs the rotation and aborts at the N-th checkpoint: after
//! a step's value is recorded, after it is written, and after it is marked
//! done. The parent then runs the rotation again and checks that every
//! secret was replaced exactly once and that the secret handed over is the
//! one stored. N grows until the child finishes without reaching it.

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use super::abort::ABORT_AT;
use super::checks::rotated_once;
use super::fixture::{run, server};

/// The configuration the child rotates.
const CONFIG: &str = "EPISTLE_TEST_ROTATE_CONFIG";

const NOW: u64 = 1_900_000_000;

/// The child: rotate the configuration the parent names, then stop. Without
/// the variable it is an ordinary test that does nothing.
#[test]
fn child_rotates_until_the_switch() {
	let Some(config) = std::env::var_os(CONFIG) else {
		return;
	};
	let ran = run(std::path::Path::new(&config), NOW);
	assert_eq!(ran.code, std::process::ExitCode::SUCCESS, "{}", ran.status);
}

#[test]
fn a_run_killed_at_any_checkpoint_is_finished_by_the_next_without_rotating_twice() {
	let mut killed = 0;
	for at in 1.. {
		let server = server();
		let status = Command::new(std::env::current_exe().expect("test binary"))
			.args([
				"--exact",
				"cli::rotate::run::tests::kill::child_rotates_until_the_switch",
				"--test-threads=1",
			])
			.env(CONFIG, &server.config)
			.env(ABORT_AT, at.to_string())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.expect("run the child");
		if status.success() {
			// The run has fewer checkpoints than `at`: it finished, and a
			// fresh run on that server starts again from the beginning.
			assert!(
				!server.data_dir.join("rotate/journal.json").exists(),
				"a finished child left its journal"
			);
			break;
		}
		assert_eq!(
			status.signal(),
			Some(libc::SIGABRT),
			"the child stopped at checkpoint {at} for another reason"
		);
		killed += 1;
		assert!(
			server.data_dir.join("rotate/journal.json").exists(),
			"checkpoint {at} came before the journal was written"
		);
		let ran = run(&server.config, NOW + 60);
		assert_eq!(
			ran.code,
			std::process::ExitCode::SUCCESS,
			"after a kill at checkpoint {at}: {}",
			ran.status
		);
		let result = rotated_once(&server, &ran.out);
		assert_eq!(result["resumed"], true, "checkpoint {at}");
	}
	// Six steps, three checkpoints each.
	assert_eq!(killed, 18, "the run did not stop where it should have");
}
