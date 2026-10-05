//! Positive paths for `epistle stack`: every subcommand and the
//! `--json` flag, driving the real binary against a stub `podup`
//! placed first on `PATH`. The error and refusal paths live in
//! `tests/stack_podup_errors.rs`; the helpers are shared from
//! `tests/stack_podup_helpers.rs`. Each test pins the exact argv
//! podup received so a regression in argv order or in the
//! passed flags is one assert away.

#[cfg(unix)]
#[path = "stack_podup_helpers.rs"]
mod helpers;
#[cfg(unix)]
use helpers::{
	binary, data_dir_with_compose, install_podup_shim, path_with_shim_first, ps_shim,
	read_argv_log, recorder_shim, run_streaming, run_with_podup, write_config, write_ps_fixture,
};
#[cfg(unix)]
use std::process::Stdio;

#[cfg(unix)]
#[test]
fn up_passes_the_compose_flag_and_dash_d_to_podup() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let (output, argv) = run_streaming(
		&["stack", "--config", cfg.to_str().unwrap(), "up"],
		&shim_dir,
		&argv_log,
	);
	assert!(
		output.status.success(),
		"up should propagate the recorder's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"up",
			"-d"
		],
		"up must call `podup --version` and then `podup -f <compose> up -d`"
	);
}

#[cfg(unix)]
#[test]
fn down_passes_only_down_to_podup_never_volumes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let (output, argv) = run_streaming(
		&["stack", "--config", cfg.to_str().unwrap(), "down"],
		&shim_dir,
		&argv_log,
	);
	assert!(
		output.status.success(),
		"down should propagate the recorder's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"down"
		],
		"down must call `podup --version` and then `podup -f <compose> down`"
	);
	for token in &argv {
		assert_ne!(
			token, "-v",
			"down must never pass `-v` to podup; the compose volumes hold the database"
		);
		assert!(
			!token.starts_with("--volumes"),
			"down must never pass `--volumes` to podup; the compose volumes hold the database"
		);
	}
}

#[cfg(unix)]
#[test]
fn ps_parses_the_canned_json_and_prints_the_table() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let canned = write_ps_fixture(dir.path());
	install_podup_shim(&shim_dir, &ps_shim(&argv_log, &canned));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "ps"],
		&shim_dir,
	);
	assert!(
		output.status.success(),
		"ps should propagate the recorder's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let argv = read_argv_log(&argv_log);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"ps",
			"--format",
			"json"
		],
		"ps must call `podup --version` and then `podup -f <compose> ps --format json`"
	);
	let stdout = String::from_utf8_lossy(&output.stdout);
	let line = stdout
		.lines()
		.find(|line| line.starts_with("mail\t"))
		.unwrap_or_else(|| panic!("stdout must carry the parsed table; got: {stdout}"));
	// The fixture has an empty `Health` and two publishers; the
	// table cell for health is `-`, the cell for ports has both
	// `25/tcp` and `587/tcp` joined by a comma.
	assert!(
		line.contains("running\t-"),
		"health column must be `-` for empty health; line: {line}"
	);
	assert!(
		line.contains("0.0.0.0:25->25/tcp"),
		"port cell must carry the SMTP mapping; line: {line}"
	);
	assert!(
		line.contains("0.0.0.0:587->587/tcp"),
		"port cell must carry the submission mapping; line: {line}"
	);
}

#[cfg(unix)]
#[test]
fn ps_json_prints_the_parsed_list_as_stable_json() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let canned = write_ps_fixture(dir.path());
	install_podup_shim(&shim_dir, &ps_shim(&argv_log, &canned));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "ps", "--json"],
		&shim_dir,
	);
	assert!(
		output.status.success(),
		"ps --json should propagate the recorder's exit 0; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8_lossy(&output.stdout);
	let parsed: serde_json::Value =
		serde_json::from_str(stdout.trim()).expect("ps --json output is valid JSON");
	let array = parsed.as_array().expect("top level is an array");
	assert_eq!(array.len(), 1, "the fixture has one row; got: {parsed}");
	let row = &array[0];
	assert_eq!(row["Service"], "mail");
	assert_eq!(row["State"], "running");
	assert_eq!(row["Health"], "");
	// The stable shape must not carry the extra unknown field:
	// the parser ignores it on input and the serialiser does not
	// re-emit fields it does not know about.
	assert!(
		row.get("ExtraFutureField").is_none(),
		"the unknown fixture field must not appear in the re-serialised shape"
	);
}

#[cfg(unix)]
#[test]
fn logs_passes_the_verb_follow_and_the_service_position_to_podup() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let (_output, argv) = run_streaming(
		&[
			"stack",
			"--config",
			cfg.to_str().unwrap(),
			"logs",
			"--follow",
			"mail",
		],
		&shim_dir,
		&argv_log,
	);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"logs",
			"--follow",
			"mail"
		],
		"logs --follow <service> must invoke `podup -f <compose> logs --follow <service>`"
	);
}

#[cfg(unix)]
#[test]
fn restart_passes_the_verb_and_the_service_position_to_podup() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let (_output, argv) = run_streaming(
		&[
			"stack",
			"--config",
			cfg.to_str().unwrap(),
			"restart",
			"mail",
		],
		&shim_dir,
		&argv_log,
	);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"restart",
			"mail"
		],
		"restart <service> must invoke `podup -f <compose> restart <service>`"
	);
}

#[cfg(unix)]
#[test]
fn logs_passes_the_verb_and_a_service_named_down() {
	// A service called `down` is the regression test for the verb
	// omission: with the verb absent, podup receives `-f <compose>
	// down` and stops the entire stack. The argv must keep
	// `logs` before the positional so the trailing `down` lands
	// as a service name, not a verb.
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let (_output, argv) = run_streaming(
		&["stack", "--config", cfg.to_str().unwrap(), "logs", "down"],
		&shim_dir,
		&argv_log,
	);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"logs",
			"down"
		],
		"logs down must invoke `podup -f <compose> logs down`; never `podup -f <compose> down`"
	);
}

/// Sabotage landing place for the `down` test: a regression
/// comment plus a positive control that the flag is absent.
/// A reviewer reading the diff follows the comment to the
/// `run_inherited` call site in `src/cli/stack.rs` and
/// temporarily re-introduces `&["down", "--volumes"]` (or
/// `-v`) to confirm the
/// `down_passes_only_down_to_podup_never_volumes` test turns
/// red. Then they undo the edit and the suite is green again.
#[cfg(unix)]
#[test]
fn down_sabotage_documents_where_a_volume_flag_would_turn_red() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	install_podup_shim(&shim_dir, &recorder_shim(&argv_log));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let (_output, argv) = run_streaming(
		&["stack", "--config", cfg.to_str().unwrap(), "down"],
		&shim_dir,
		&argv_log,
	);
	assert!(
		!argv
			.iter()
			.any(|token| token == "-v" || token.starts_with("--volumes")),
		"sabotage control: with the flag absent, no -v or --volumes token lands in the argv"
	);
}

#[cfg(unix)]
#[test]
fn stack_accepts_config_after_the_subcommand() {
	// The `--config` flag belongs to the `stack` parent, not to
	// any one subcommand, so clap parses it anywhere along the
	// `epistle stack <sub> ...` argument chain. The documented
	// `epistle stack ps --config F` shape rejected the binary
	// before this commit with `unexpected argument '--config'`
	// and exited 2; the test runs that exact argv against a
	// working podup stub and asserts the parse is accepted and
	// the same `ps --format json` argv lands in podup.
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let canned = write_ps_fixture(dir.path());
	install_podup_shim(&shim_dir, &ps_shim(&argv_log, &canned));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let output = run_with_podup(
		&["stack", "ps", "--config", cfg.to_str().unwrap()],
		&shim_dir,
	);
	assert!(
		output.status.success(),
		"`--config` after the subcommand must be accepted; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let argv = read_argv_log(&argv_log);
	assert_eq!(
		argv,
		vec![
			"--version",
			"-f",
			data_dir.join("compose/compose.yaml").to_str().unwrap(),
			"ps",
			"--format",
			"json"
		],
		"`epistle stack ps --config F` must invoke `podup --version` and then `podup -f <compose> ps --format json`"
	);
}

#[cfg(unix)]
#[test]
fn ps_table_write_failure_makes_epistle_exit_nonzero() {
	// A write failure on the table output must surface as a
	// non-zero exit, not be silently swallowed by `let _ =`.
	// Redirecting `epistle stack ps` stdout to `/dev/full`
	// (Linux: every write returns `ENOSPC`) reproduces the
	// condition. Before this commit the binary exited 0 with
	// an empty stdout.
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let canned = write_ps_fixture(dir.path());
	install_podup_shim(&shim_dir, &ps_shim(&argv_log, &canned));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let mut cmd = std::process::Command::new(binary());
	cmd.args(["stack", "--config", cfg.to_str().unwrap(), "ps"]);
	cmd.env("PATH", path_with_shim_first(&shim_dir));
	cmd.env_remove("CLICOLOR_FORCE");
	cmd.env("NO_COLOR", "1");
	cmd.stdin(Stdio::null())
		.stdout(std::fs::File::create("/dev/full").expect("open /dev/full"))
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert_ne!(
		output.status.code(),
		Some(0),
		"a write failure on stdout must make epistle exit non-zero; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
}

#[cfg(unix)]
#[test]
fn ps_json_write_failure_makes_epistle_exit_nonzero() {
	// The same write-failure gate as the table path, but for
	// `--json`. Before this commit the binary exited 0 with an
	// empty stdout even when the destination rejected the
	// serialised JSON.
	let dir = tempfile::tempdir().expect("tempdir");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	let canned = write_ps_fixture(dir.path());
	install_podup_shim(&shim_dir, &ps_shim(&argv_log, &canned));
	let data_dir = data_dir_with_compose(dir.path());
	let cfg = write_config(&data_dir);
	let mut cmd = std::process::Command::new(binary());
	cmd.args(["stack", "--config", cfg.to_str().unwrap(), "ps", "--json"]);
	cmd.env("PATH", path_with_shim_first(&shim_dir));
	cmd.env_remove("CLICOLOR_FORCE");
	cmd.env("NO_COLOR", "1");
	cmd.stdin(Stdio::null())
		.stdout(std::fs::File::create("/dev/full").expect("open /dev/full"))
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert_ne!(
		output.status.code(),
		Some(0),
		"a write failure on `--json` stdout must make epistle exit non-zero; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
}
