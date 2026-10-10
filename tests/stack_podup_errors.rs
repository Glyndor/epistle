//! Error and refusal paths for `epistle stack`: a too-old podup
//! version, a missing `podup` binary, a missing compose file,
//! and a failing `podup` exit code. The positive subcommand
//! coverage lives in `tests/stack_podup.rs`; the helpers are
//! shared from `tests/stack_podup_helpers.rs`. Every test
//! asserts the operator-facing message as well as the exit
//! code: an exit code alone is not enough to keep a wrong
//! diagnosis out of the field.

#[cfg(unix)]
#[path = "stack_podup_helpers.rs"]
mod helpers;
#[cfg(unix)]
use helpers::{
	binary, data_dir_with_compose, install_podup_shim, read_argv_log, recorder_shim,
	run_with_podup, write_config,
};
use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};

#[cfg(unix)]
#[test]
fn podup_exiting_nonzero_makes_epistle_exit_nonzero_with_the_command_named() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	// Shim exits 0 for `--version`, 3 for everything else, so
	// the error path can fire on a meaningful status code.
	let body = format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 if [ \"$1\" = \"--version\" ]; then\n\
		 \tprintf '\\npodup version v5.10.13\\n\\n'\n\
		 \texit 0\n\
		 fi\n\
		 exit 3\n",
		argv_log = argv_log.display()
	);
	install_podup_shim(&shim_dir, &body);
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(3),
		"epistle must propagate the podup exit code 3; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("`podup -f ") && stderr.contains("up") && stderr.contains("exited"),
		"stderr must name the failed podup command; got: {stderr}"
	);
}

#[cfg(unix)]
#[test]
fn podup_version_below_the_floor_is_refused_with_both_versions_named() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	// The shim claims to be 5.9.0; the floor is 5.10.13. The
	// `epistle stack` exit code is non-zero and the message
	// names both versions so the operator can tell which one
	// is wrong.
	let body = format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 if [ \"$1\" = \"--version\" ]; then\n\
		 \tprintf '\\npodup version v5.9.0\\n\\n'\n\
		 \texit 0\n\
		 fi\n\
		 exit 0\n",
		argv_log = argv_log.display()
	);
	install_podup_shim(&shim_dir, &body);
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(1),
		"a too-old podup must make epistle exit 1; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("5.9.0") && stderr.contains("5.10.13"),
		"the refused-version error must name both the found version (5.9.0) and the required floor (5.10.13); got: {stderr}"
	);
	// The shim's argv log only has `--version`: `up` must never
	// reach podup when the floor refuses the binary.
	let argv = read_argv_log(&argv_log);
	assert_eq!(
		argv,
		vec!["--version"],
		"a too-old podup must short-circuit before any other command is run"
	);
}

#[cfg(unix)]
#[test]
fn podup_version_exit_code_is_propagated_to_epistle() {
	// A failing `podup --version` probe (anything other than 0)
	// must surface as the same exit code from `epistle stack`,
	// not be flattened to 1. Before this commit the version
	// probe always returned `ExitCode::FAILURE`, so a stub that
	// exits 3 made the binary exit 1 and the next command's
	// exit-code semantics were the only way for a non-zero
	// status to escape. The shim here exits 3 for `--version`
	// and 0 otherwise so the probe is the only thing that
	// fails.
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let body = format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 if [ \"$1\" = \"--version\" ]; then\n\
		 \texit 3\n\
		 fi\n\
		 exit 0\n",
		argv_log = argv_log.display()
	);
	install_podup_shim(&shim_dir, &body);
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(3),
		"a failing `podup --version` must propagate the probe's exit code (3); stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
}

#[cfg(unix)]
#[test]
fn missing_podup_binary_is_named_in_the_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	// `podup` is made unresolvable by pointing PATH at an
	// existing empty directory. An empty `PATH` string is not
	// equivalent: when PATH is empty, execvp falls back to the
	// current working directory, so a `./podup` left by a
	// previous test would still run and the test would observe
	// the wrong error. The empty directory sidesteps the
	// current-directory fallback while keeping the test
	// reproducible across hosts that install `podup` system-wide.
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let empty_path = dir.path().join("empty_path");
	std::fs::create_dir_all(&empty_path).expect("mkdir empty_path");
	// Defense against a sabotaged test that drops a podup in
	// the working directory and expects the missing-binary
	// branch: make the CWD of the child process the empty
	// directory, not the host shell. Without this, a `./podup`
	// left behind would be picked up by execvp and the
	// missing-binary assertion would observe the wrong exit
	// and the wrong stderr.
	let mut cmd = Command::new(binary());
	cmd.args(["stack", "--config", cfg.to_str().unwrap(), "up"]);
	cmd.env("PATH", &empty_path);
	cmd.current_dir(&empty_path);
	cmd.env_remove("CLICOLOR_FORCE");
	cmd.env("NO_COLOR", "1");
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert_eq!(
		output.status.code(),
		Some(1),
		"a missing podup must make epistle exit 1; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("`podup`") && stderr.contains("required"),
		"the missing-podup error must name the binary and call it required; got: {stderr}"
	);
	assert!(
		stderr.contains("apt install podup") || stderr.contains("apt.glyndor.net"),
		"the missing-podup error must point at the install command; got: {stderr}"
	);
}

#[cfg(unix)]
#[test]
fn missing_podup_does_not_search_the_current_directory() {
	// Regression for the empty-PATH-vs-empty-dir distinction:
	// a `./podup` left in the child's working directory must
	// not be picked up by execvp when `podup` is supposed to
	// be missing. The two directories are split on purpose: the
	// `cwd_dir` carries the sibling podup and is the child's
	// CWD, while `empty_path` is what `PATH` points at. With
	// the old `PATH = ""` setup execvp would fall back to
	// `cwd_dir` and run the sibling shim, so the missing-
	// binary branch would never fire; pointing PATH at a
	// separate empty directory removes that fallback because
	// execvp only searches PATH when PATH is non-empty.
	let dir = tempfile::tempdir().expect("tempdir");
	let cwd_dir = dir.path().join("cwd");
	let empty_path = dir.path().join("empty_path");
	std::fs::create_dir_all(&cwd_dir).expect("mkdir cwd");
	std::fs::create_dir_all(&empty_path).expect("mkdir empty_path");
	let argv_log = cwd_dir.join("argv.log");
	// The shim looks like a real podup: it prints the floor
	// so a child that finds it would see the version probe
	// succeed and move on to `up`. If `epistle stack` ran
	// this shim, `argv_log` would carry `--version` followed
	// by the subcommand argv. The test asserts the shim is
	// never invoked.
	let body = format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 printf '\\npodup version v{PODUP_FLOOR}\\n\\n'\n\
		 exit 0\n",
		argv_log = argv_log.display(),
		PODUP_FLOOR = "5.10.13"
	);
	// The sibling podup lives in CWD, not in the directory
	// PATH points at. If PATH is reverted to "" and the CWD
	// fallback kicks in, execvp would pick this shim up and
	// the test would go red.
	let sibling_podup = cwd_dir.join("podup");
	std::fs::write(&sibling_podup, &body).expect("write sibling podup");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&sibling_podup, std::fs::Permissions::from_mode(0o755))
			.expect("chmod sibling podup");
	}
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let mut cmd = Command::new(binary());
	cmd.args(["stack", "--config", cfg.to_str().unwrap(), "up"]);
	cmd.env("PATH", &empty_path);
	// CWD holds the sibling podup. PATH points at a
	// different, empty directory. execvp will only search
	// PATH when PATH is non-empty, so the CWD fallback
	// never applies and the missing-binary branch fires.
	cmd.current_dir(&cwd_dir);
	cmd.env_remove("CLICOLOR_FORCE");
	cmd.env("NO_COLOR", "1");
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert_eq!(
		output.status.code(),
		Some(1),
		"a missing podup must make epistle exit 1; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("required"),
		"the missing-podup error must name the binary and call it required; got: {stderr}"
	);
	assert!(
		!argv_log.exists(),
		"the `./podup` in CWD must not be executed; argv_log at {} must not exist",
		argv_log.display()
	);
}

#[cfg(unix)]
#[test]
fn missing_compose_file_names_the_path_in_the_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	// No compose file is written: the `data_dir` exists, the
	// `compose/` subdir is missing, and the error must name
	// the path the operator needs to create.
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(1),
		"a missing compose file must make epistle exit 1; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	let compose_path = data_dir.join("compose/compose.yaml");
	assert!(
		stderr.contains(compose_path.to_str().unwrap()),
		"the missing-compose error must name the path the operator needs to create; got: {stderr}"
	);
	assert!(
		stderr.contains("epistle init"),
		"the missing-compose error must tell the operator to run `epistle init`; got: {stderr}"
	);
	// The shim never runs: the missing-compose check
	// short-circuits before podup is touched, so the argv log
	// either does not exist or is empty. Reading it would race
	// the missing-file case (a NotFound is the same answer as
	// an empty log).
	let argv: Vec<String> = if argv_log.exists() {
		read_argv_log(Path::new(&argv_log))
	} else {
		Vec::new()
	};
	assert!(
		argv.is_empty(),
		"a missing compose file must short-circuit before podup is invoked; got: {argv:?}"
	);
}
