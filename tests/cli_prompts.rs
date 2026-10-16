//! The CLI run from a script, with no terminal: a destructive command without
//! `--yes` exits 2 with a message naming `--yes`, writes nothing to stdout
//! and changes nothing, and `-y` lets it through; a password is still read
//! from a pipe; an unknown account and a static one get different errors.

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
