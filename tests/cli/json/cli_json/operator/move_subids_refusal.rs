//! `epistle move-subids` rewrites `/etc/subuid` and `/etc/subgid`, so a run
//! that is not the one the package script makes has to end before it reads
//! a configuration or touches a file: without root it is refused, and ids
//! that are not numbers are a usage error.

use crate::harness::{env, epistle};

fn move_subids(args: &[&str]) -> std::process::Output {
	let mut full = vec!["move-subids"];
	full.extend_from_slice(args);
	epistle(&full, b"")
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_run_that_is_not_root_is_refused_before_anything_is_read() {
	let env = env("");
	// Under `fakeroot` the process believes it is root, and then the account
	// the command moves is the first thing it cannot find; either way it
	// stops before it has a block to move.
	for config in [env.config.as_str(), "/nonexistent/mail.toml"] {
		let output = move_subids(&[
			"--uid-start",
			"900000",
			"--gid-start",
			"900000",
			"--config",
			config,
		]);
		assert_eq!(output.status.code(), Some(1), "{config}");
		assert!(output.stdout.is_empty(), "{config}");
		let message = stderr(&output);
		assert!(
			message.contains("must run as root") || message.contains("no glyndor-epistle account"),
			"{config}: {message}"
		);
	}
}

#[test]
fn ids_that_are_not_numbers_are_a_usage_error() {
	for args in [
		&["--uid-start", "abc", "--gid-start", "900000"][..],
		&["--uid-start", "900000", "--gid-start", "-1"][..],
		&["--uid-start", "900000"][..],
		&["--gid-start", "900000"][..],
		&[][..],
	] {
		let output = move_subids(args);
		assert_eq!(output.status.code(), Some(2), "{args:?}");
		assert!(output.stdout.is_empty(), "{args:?}");
	}
}
