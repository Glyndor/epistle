//! The warning podup prints for a port published on every interface, and
//! the ports the stack publishes on purpose.
//!
//! The stub `podup` prints the warning the engine prints on every `up`:
//! for a port the stack publishes on purpose, and for one it does not.
//! The first is replaced by one note, so the warning that is always there
//! stops hiding the one that matters; the second stays exactly as podup
//! wrote it, because that one is about a port nobody asked to reach the
//! public internet.

#[cfg(unix)]
#[path = "stack_podup_helpers.rs"]
mod helpers;
#[cfg(unix)]
use helpers::{
	data_dir_with_compose, install_podup_shim, run_with_podup, stderr_shim, warning,
	write_config_with_listeners,
};

/// The warning about a port the stack publishes on purpose is replaced by
/// one note, and the note is printed once per run.
#[cfg(unix)]
#[test]
fn up_replaces_the_warning_about_a_port_the_stack_publishes_on_purpose() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let data_dir = data_dir_with_compose(dir.path());
	// The mail listeners bind the wildcard, so the host reaches them on
	// every address it owns: that is what the warning is about, and it
	// is what the stack wants.
	let cfg = write_config_with_listeners(&data_dir, &[("smtp", "0.0.0.0", 25)]);
	install_podup_shim(&shim_dir, &stderr_shim(&argv_log, &[warning(25)]));
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert!(
		output.status.success(),
		"up should propagate podup's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		!stderr.contains("podup: warning:"),
		"the warning about a port the stack publishes on purpose must not reach the operator; stderr: {stderr}"
	);
	assert!(
		stderr.contains("note: port 25 is public on purpose (bind 0.0.0.0)"),
		"the note must replace the warning; stderr: {stderr}"
	);
	assert_eq!(
		stderr.matches("note:").count(),
		1,
		"the note is printed once per run, however many ports podup warned about; stderr: {stderr}"
	);
}

/// The warning about a port the stack does not publish on purpose stays
/// exactly as podup printed it: that one is about a port nobody asked to
/// reach the public internet.
#[cfg(unix)]
#[test]
fn up_keeps_the_warning_about_a_port_the_stack_does_not_publish_on_purpose() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let data_dir = data_dir_with_compose(dir.path());
	// The listener binds loopback, so the stack does not publish it on
	// every interface; the warning is about the mapping the operator
	// wrote in the override, and it is the one that has to be read.
	let cfg = write_config_with_listeners(&data_dir, &[("metrics", "127.0.0.1", 9090)]);
	install_podup_shim(&shim_dir, &stderr_shim(&argv_log, &[warning(9090)]));
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert!(
		output.status.success(),
		"up should propagate podup's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains(&warning(9090)),
		"the warning must stay exactly as podup printed it; stderr: {stderr}"
	);
	assert!(
		!stderr.contains("note:"),
		"no warning was replaced, so there is no note; stderr: {stderr}"
	);
}

/// Every line podup printed that is not a warning about a published port
/// reaches the operator, in the same run that replaces one warning.
#[cfg(unix)]
#[test]
fn up_keeps_the_lines_podup_printed_that_are_not_about_a_published_port() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config_with_listeners(&data_dir, &[("smtp", "0.0.0.0", 25)]);
	install_podup_shim(
		&shim_dir,
		&stderr_shim(
			&argv_log,
			&[
				warning(25),
				"podup: creating container epistle-mail-1".to_string(),
			],
		),
	);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert!(
		output.status.success(),
		"up should propagate podup's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("podup: creating container epistle-mail-1"),
		"a line that is not a warning must reach the operator untouched; stderr: {stderr}"
	);
	assert!(
		!stderr.contains("podup: warning:"),
		"the warning about the port the stack publishes on purpose is replaced; stderr: {stderr}"
	);
}

/// The exit code podup leaves behind is the exit code of `stack up`: the
/// filter reads the output, it does not swallow the failure.
#[cfg(unix)]
#[test]
fn up_keeps_the_exit_code_podup_left_behind() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config_with_listeners(&data_dir, &[("smtp", "0.0.0.0", 25)]);
	install_podup_shim(&shim_dir, &failing_shim(&argv_log, 3));
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(3),
		"the exit code podup left behind must be the exit code of `stack up`; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
}

/// A podup stub that fails with the given exit code.
#[cfg(unix)]
fn failing_shim(argv_log: &std::path::Path, code: i32) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 if [ \"$1\" = \"--version\" ]; then\n\
		 \tprintf '\\npodup version v5.15.4\\n\\n'\n\
		 \texit 0\n\
		 fi\n\
		 exit {code}\n",
		argv_log = argv_log.display(),
		code = code
	)
}
