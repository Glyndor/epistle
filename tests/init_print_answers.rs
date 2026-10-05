//! Integration test for `epistle init --print-answers`: the printable
//! output must be byte-clean (no escape codes, no decoration) and must
//! deserialise back into the production `Answers` once `hostname` and
//! `domains` are filled in. Modeled on `tests/cli_stdout_clean.rs`.

use std::path::Path;
use std::process::{Command, Stdio};

use epistle::cli::Answers;

fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

const ESCAPE: &[u8] = b"\x1b[";

fn with_color_env(cmd: &mut Command) {
	cmd.env("CLICOLOR_FORCE", "1");
	cmd.env("CLICOLOR", "1");
	cmd.env("TERM", "xterm-256color");
	cmd.env_remove("NO_COLOR");
}

fn has_ansi_escape(bytes: &[u8]) -> bool {
	bytes.windows(ESCAPE.len()).any(|window| window == ESCAPE)
}

#[test]
fn print_answers_stdout_is_clean() {
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--print-answers"]);
	with_color_env(&mut cmd);
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"init --print-answers exit code: {:?}",
		output.status
	);
	assert!(
		!has_ansi_escape(&output.stdout),
		"init --print-answers stdout carries an ANSI escape sequence: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);
}

#[test]
fn print_answers_output_deserialises_into_answers() {
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--print-answers"]);
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(output.status.success());
	let text = std::str::from_utf8(&output.stdout).expect("utf-8 stdout");
	// The printable template is TOML; deserialise the EXACT stdout bytes
	// into the production struct with no preprocessing so any drift in
	// the printed template shows up here.
	let parsed: Answers = toml::from_str(text).unwrap_or_else(|error| {
		panic!("stdout is not valid TOML: {error}\n--- stdout ---\n{text}")
	});
	assert!(
		parsed.validate().is_ok(),
		"template must pass Answers::validate"
	);
	assert_eq!(parsed.hostname, "mail.example.org");
	assert_eq!(parsed.domains, vec!["example.org".to_string()]);
}

#[test]
fn print_answers_carries_nothing_on_stderr() {
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--print-answers"]);
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(output.status.success());
	let stderr = std::str::from_utf8(&output.stderr).expect("utf-8 stderr");
	assert!(
		stderr.trim().is_empty(),
		"init --print-answers wrote to stderr: {stderr}"
	);
}
