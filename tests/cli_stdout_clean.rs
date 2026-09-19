//! The four data-producing CLI commands keep stdout byte-clean: no escape
//! codes, no progress frames, no decoration of any kind. An escape sequence
//! slipped into the stream would corrupt the artefact (a gzip header, an mbox
//! stream, a private key) and the corruption would not show up until a
//! restore failed, far from the command that caused it.
//!
//! Each test spawns the `epistle` binary through `CARGO_BIN_EXE_epistle` with
//! `CLICOLOR_FORCE=1`, `TERM=xterm-256color` and `NO_COLOR` removed, capturing
//! both stdout and stderr. stderr is allowed to be coloured; stdout must not
//! contain `\x1b[` (the CSI introducer) under any test in this file. A positive
//! control runs `config-check` against a missing file under the same
//! environment: stderr then MUST carry `\x1b[`, proving the colour path is
//! actually exercised and the absence of escapes on stdout is not a vacuous
//! pass.

use std::path::Path;
use std::process::{Command, Stdio};

/// The CLI binary path. `CARGO_BIN_EXE_<name>` is set by Cargo when an
/// integration test compiles against a binary in the same package.
fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

/// The escape-byte introducer the rest of an ANSI sequence follows.
const ESCAPE: &[u8] = b"\x1b[";

/// Apply the colour-forcing environment and clear any inherited `NO_COLOR`.
fn with_color_env(cmd: &mut Command) {
	cmd.env("CLICOLOR_FORCE", "1");
	cmd.env("CLICOLOR", "1");
	cmd.env("TERM", "xterm-256color");
	cmd.env_remove("NO_COLOR");
}

fn has_ansi_escape(bytes: &[u8]) -> bool {
	bytes.windows(ESCAPE.len()).any(|window| window == ESCAPE)
}

/// Byte offset of the first escape sequence, for a failure message that must
/// not print the stream itself: the keygen commands write key material there.
fn escape_offset(bytes: &[u8]) -> Option<usize> {
	bytes
		.windows(ESCAPE.len())
		.position(|window| window == ESCAPE)
}

/// Spawn `args` against the binary with the colour-forcing environment and
/// `NO_COLOR` cleared. Returns the captured stdout and stderr bytes and the
/// exit status.
fn run_capture(args: &[&str]) -> (Vec<u8>, Vec<u8>, std::process::ExitStatus) {
	let mut cmd = Command::new(binary());
	cmd.args(args);
	with_color_env(&mut cmd);
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	(output.stdout, output.stderr, output.status)
}

/// Restrict a config file's mode to 0600. `Config::load` rejects world- or
/// group-readable files before any command runs, and the `tempfile` default
/// of 0o644 would otherwise trip that gate.
#[cfg(unix)]
fn restrict_config_permissions(path: &Path) {
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
		.expect("restrict config");
}

#[cfg(not(unix))]
fn restrict_config_permissions(_path: &Path) {}

/// `storage-keygen`: the printable artefact is a single base64 line on stdout.
/// No escape codes anywhere on stdout, and the exit code is success.
#[test]
fn storage_keygen_stdout_is_clean() {
	let (stdout, _stderr, status) = run_capture(&["storage-keygen"]);
	assert!(status.success(), "storage-keygen exit code: {status:?}");
	assert_eq!(
		escape_offset(&stdout),
		None,
		"storage-keygen stdout carries an ANSI escape sequence at this byte offset"
	);
}

/// `oauth-keygen`: four lines on stdout (two `# ...` comment lines plus the
/// base64 private and public points). All of them must reach the operator's
/// terminal byte-for-byte; no escape codes anywhere on stdout.
#[test]
fn oauth_keygen_stdout_is_clean() {
	let (stdout, _stderr, status) = run_capture(&["oauth-keygen"]);
	assert!(status.success(), "oauth-keygen exit code: {status:?}");
	assert_eq!(
		escape_offset(&stdout),
		None,
		"oauth-keygen stdout carries an ANSI escape sequence at this byte offset"
	);
}

/// `backup` writes a gzip-compressed tar archive to stdout. The first two bytes
/// must be the gzip magic (`1f 8b`) and no escape code may precede them. An
/// empty `data_dir` is the simplest case: the archive still has the gzip
/// header and the two trailing zero blocks. The bytes between are binary
/// (gzip), so the test asserts on bytes rather than UTF-8.
#[test]
fn backup_stdout_is_clean_gzip_magic() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("mkdir data dir");
	let config = dir.path().join("mail.toml");
	let config_text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	std::fs::write(&config, config_text).expect("write config");
	restrict_config_permissions(&config);

	let (stdout, _stderr, status) = run_capture(&["backup", "--config", config.to_str().unwrap()]);
	assert!(status.success(), "backup exit code: {status:?}");
	assert!(
		!has_ansi_escape(&stdout),
		"backup stdout contains an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&stdout)
	);
	assert!(
		stdout.starts_with(b"\x1f\x8b"),
		"backup stdout does not start with the gzip magic (1f 8b)"
	);
}

/// `export` writes an mbox stream to stdout. The first line is the canonical
/// `From MAILER-DAEMON@localhost` separator; a delivered message in the
/// account's INBOX is required so the export is not empty (an empty export
/// would pass the assertion trivially without proving the message data also
/// reaches stdout cleanly).
#[test]
fn export_stdout_is_clean_mbox_header() {
	use epistle::imap::mailbox;
	use epistle::storage::MessageCrypto;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("mkdir data dir");
	let config = dir.path().join("mail.toml");
	let config_text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	std::fs::write(&config, config_text).expect("write config");
	restrict_config_permissions(&config);

	// Deliver a plaintext message into alice's INBOX through the same
	// `mailbox::append` path the rest of the test suite uses; crypto is
	// disabled so the integration test does not depend on a private key.
	let crypto = MessageCrypto::disabled();
	mailbox::append(
		&data_dir,
		"alice",
		"INBOX",
		&[],
		b"Subject: hi\r\n\r\nsecret export body\r\n",
		&crypto,
	)
	.expect("append to inbox");

	let (stdout, _stderr, status) = run_capture(&[
		"export",
		"--config",
		config.to_str().unwrap(),
		"--account",
		"alice",
	]);
	assert!(status.success(), "export exit code: {status:?}");
	assert!(
		!has_ansi_escape(&stdout),
		"export stdout contains an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&stdout)
	);
	let text = std::str::from_utf8(&stdout).expect("utf-8 export");
	assert!(
		text.starts_with("From MAILER-DAEMON@localhost"),
		"export stdout does not start with the canonical mbox separator: {text:?}"
	);
	assert!(
		text.contains("secret export body"),
		"export stdout missing the delivered message body: {text:?}"
	);
}

/// Positive control: run `config-check` against a missing file. The exit
/// code is non-zero and stderr MUST carry an ANSI escape sequence (the bold
/// red `error:` prefix). This proves the colour path is real and the previous
/// four tests are not passing because the binary simply never produces
/// colour under any circumstances.
#[test]
fn config_check_missing_file_stderr_carries_color() {
	let mut cmd = Command::new(binary());
	cmd.args(["config-check", "--config", "/nonexistent/mail.toml"]);
	with_color_env(&mut cmd);
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	let stdout = output.stdout;
	let stderr = output.stderr;
	let status = output.status;

	assert!(
		!status.success(),
		"config-check with a missing file should fail"
	);
	assert!(
		!has_ansi_escape(&stdout),
		"config-check stdout carries an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&stdout)
	);
	assert!(
		has_ansi_escape(&stderr),
		"config-check stderr does NOT carry an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&stderr)
	);
}

/// Honour the standard `NO_COLOR` override: with `NO_COLOR=1`, the same
/// failing `config-check` command above writes the `error:` line on stderr
/// without ANSI escapes. Confirms the opt-out from the colour path the rest
/// of this file relies on.
#[test]
fn config_check_missing_file_respects_no_color() {
	let mut cmd = Command::new(binary());
	cmd.args(["config-check", "--config", "/nonexistent/mail.toml"]);
	cmd.env("NO_COLOR", "1");
	cmd.env("TERM", "dumb");
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	let stderr = output.stderr;
	let status = output.status;
	assert!(
		!status.success(),
		"config-check with a missing file should fail"
	);
	assert!(
		!has_ansi_escape(&stderr),
		"NO_COLOR=1 was ignored; stderr still carries ANSI: {:?}",
		String::from_utf8_lossy(&stderr)
	);
}

/// `NO_COLOR=1` must silence stderr even when no other knob is pulling it
/// toward colour: no `CLICOLOR_FORCE`, a colour-capable `TERM`. A piped
/// stderr alone turns colour off in `anstream`, so this test removes that
/// safety net by setting a colour-friendly `TERM` and proves the
/// implementation reads `NO_COLOR` instead of relying on the pipe.
#[test]
fn config_check_respects_no_color_without_clicolor_force() {
	let mut cmd = Command::new(binary());
	cmd.args(["config-check", "--config", "/nonexistent/mail.toml"]);
	cmd.env("NO_COLOR", "1");
	cmd.env("TERM", "xterm-256color");
	cmd.env_remove("CLICOLOR_FORCE");
	cmd.env_remove("CLICOLOR");
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	let stderr = output.stderr;
	let status = output.status;
	assert!(
		!status.success(),
		"config-check with a missing file should fail"
	);
	assert!(
		!has_ansi_escape(&stderr),
		"NO_COLOR=1 was ignored; stderr still carries ANSI: {:?}",
		String::from_utf8_lossy(&stderr)
	);
}

/// `reports` (the DMARC / TLS-RPT summary) routes its config-load failure
/// through `style::error` like every other config-taking command, not
/// through a raw `eprintln!`. A raw `eprintln!("error: ...")` reaches
/// stderr as plain text, while `style::error` writes through the same
/// `anstream` wrapper the rest of the CLI uses; with `CLICOLOR_FORCE=1`
/// the wrapper preserves the ANSI codes. The escape sequence is the
/// signal that the dispatch reached the styled branch; reverting the
/// arm to `eprintln!` removes the escape and the test fails.
#[test]
fn reports_missing_file_stderr_carries_color() {
	let mut cmd = Command::new(binary());
	cmd.args(["reports", "--config", "/nonexistent/mail.toml"]);
	with_color_env(&mut cmd);
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	let stdout = output.stdout;
	let stderr = output.stderr;
	let status = output.status;

	assert!(
		!status.success(),
		"reports with a missing config should fail"
	);
	assert!(
		!has_ansi_escape(&stdout),
		"reports stdout carries an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&stdout)
	);
	assert!(
		has_ansi_escape(&stderr),
		"reports stderr does NOT carry an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&stderr)
	);
}
