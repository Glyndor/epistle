//! The CLI run from a script, with no terminal: a destructive command without
//! `--yes` exits 2 with a message naming `--yes`, writes nothing to stdout
//! and changes nothing, and `-y` lets it through; a password is still read
//! from a pipe; an unknown account and a static one get different errors;
//! `init` without `--answers` keeps asking its piped questions.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn epistle(args: &[&str], stdin: &[u8]) -> Output {
	let mut child = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(args)
		.env("NO_COLOR", "1")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("spawn epistle");
	child
		.stdin
		.take()
		.expect("stdin")
		.write_all(stdin)
		.expect("write stdin");
	child.wait_with_output().expect("wait epistle")
}

fn config(dir: &Path) -> String {
	config_with(dir, "")
}

fn config_with(dir: &Path, extra: &str) -> String {
	let path = dir.join("mail.toml");
	std::fs::create_dir(dir.join("data")).expect("data dir");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}",
			dir.join("data")
		),
	)
	.expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path.to_string_lossy().into_owned()
}

#[test]
fn account_remove_without_a_terminal_needs_yes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let base = ["--config", config.as_str(), "--name", "alice"];
	let added = epistle(
		&[
			&["account-add"],
			&base[..],
			&["--address", "alice@example.org"],
		]
		.concat(),
		b"Zq8!vT3#mL0@pW6$\n",
	);
	assert!(
		added.status.success(),
		"account-add: {}",
		String::from_utf8_lossy(&added.stderr)
	);

	let remove = [&["account-remove"], &base[..], &["--queue", "drain"]].concat();
	let refused = epistle(&remove, b"y\n");
	assert_eq!(refused.status.code(), Some(2));
	assert_eq!(refused.stdout, b"", "stdout stays clean");
	assert_eq!(
		String::from_utf8_lossy(&refused.stderr),
		"error: account-remove was not confirmed; re-run with --yes to apply, or answer the question on a terminal\n"
	);
	let accounts =
		std::fs::read_to_string(dir.path().join("data/accounts.toml")).expect("accounts");
	assert!(accounts.contains("alice"), "the refusal removed nothing");

	let removed = epistle(&[&remove[..], &["-y"]].concat(), b"");
	assert!(
		removed.status.success(),
		"account-remove -y: {}",
		String::from_utf8_lossy(&removed.stderr)
	);
	assert!(String::from_utf8_lossy(&removed.stdout).starts_with("removed account alice\n"));
}

#[test]
fn an_unknown_account_and_a_static_one_get_different_errors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config_with(
		dir.path(),
		"[[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\n",
	);
	// An unknown name is a usage error (2), a static account a refusal by
	// policy (3).
	let stderr = |args: &[&str], code: i32| {
		let output = epistle(
			&[&["account"], args, &["--config", config.as_str()]].concat(),
			b"",
		);
		assert_eq!(output.status.code(), Some(code), "{args:?}");
		String::from_utf8_lossy(&output.stderr).into_owned()
	};
	assert_eq!(
		stderr(&["disable", "ghost"], 2),
		"error: no such account: ghost\n"
	);
	assert_eq!(
		stderr(&["password", "ghost"], 2),
		"error: no such account: ghost\n"
	);
	assert_eq!(
		stderr(&["disable", "bob"], 3),
		"error: account bob: edit the config file to change a static account\n"
	);
	let shown = epistle(
		&["account", "show", "bob", "--config", config.as_str()],
		b"",
	);
	assert!(
		shown.status.success(),
		"{}",
		String::from_utf8_lossy(&shown.stderr)
	);
	assert!(String::from_utf8_lossy(&shown.stdout).contains("source: static\n"));
}

#[test]
fn a_missing_account_without_a_terminal_is_still_a_usage_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let output = epistle(&["account", "show", "--config", config.as_str()], b"1\n");
	assert_eq!(output.status.code(), Some(2), "{output:?}");
	assert!(output.stdout.is_empty(), "{output:?}");
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr
			.starts_with("error: the following required arguments were not provided:\n  <NAME>\n"),
		"{stderr}"
	);
	assert!(!stderr.contains("Pick"), "nothing is offered: {stderr}");
}

#[test]
fn init_without_a_terminal_keeps_the_piped_questions_and_the_json_result() {
	// A pipe is not a terminal, so the guided flow does not apply: the
	// questions are the ones this command shipped with, they go to stderr
	// as before, and `--json` still writes the machine result to stdout.
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = format!(
		"manual\nmail.example.org\nexample.org\n\n\n\n\n{}\n{}\n{}\n\n\n\n\n\n\n",
		dir.path().join("data").display(),
		dir.path().join("etc/mail.toml").display(),
		"\n".repeat(7),
	);
	let output = epistle(&["init", "--dry-run", "--json"], answers.as_bytes());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert_eq!(output.status.code(), Some(0), "{stderr}");
	for question in [
		"mode [manual/automatic]",
		"hostname> ",
		"domains:",
		"data_dir> ",
	] {
		assert!(stderr.contains(question), "missing {question}: {stderr}");
	}
	assert!(!stderr.contains("Step 1 of 7"), "{stderr}");
	assert!(!stderr.contains("Resume"), "{stderr}");
	assert!(!stderr.contains('\u{1b}'), "{stderr}");
	let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json on stdout");
	assert_eq!(json["result"], "dry-run");
	assert!(json["plan"].as_array().is_some_and(|plan| !plan.is_empty()));
	assert!(!dir.path().join("data").exists());
}

#[test]
fn init_without_answers_stops_at_the_end_of_the_pipe() {
	// The assistant reads until the pipe ends and exits 2 without asking
	// for `--answers`.
	let output = epistle(&["init", "--dry-run"], b"manual\n");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	let stderr = String::from_utf8(output.stderr).expect("utf-8");
	assert!(stderr.contains("mode [manual/automatic]"), "{stderr}");
	assert!(stderr.contains("hostname> "), "{stderr}");
	assert!(!stderr.contains("Step 1 of 7"), "{stderr}");
	assert!(!stderr.contains("Resume"), "{stderr}");
	assert!(!stderr.contains('\u{1b}'), "{stderr}");
}
