//! Addresses typed at the CLI: a refused one says which rule it breaks.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PASSWORD: &[u8] = b"Zq8!vT3#mL0@pW6$\n";

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
	let path = dir.join("mail.toml");
	std::fs::create_dir(dir.join("data")).expect("data dir");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
			dir.join("data")
		),
	)
	.expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path.to_string_lossy().into_owned()
}

fn stderr(output: &Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn account_add_names_the_rule_an_address_breaks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let long = format!("{}@example.org", "a".repeat(65));
	let refused = epistle(
		&[
			"account",
			"--config",
			&config,
			"add",
			"bob",
			"--address",
			&long,
		],
		PASSWORD,
	);
	assert!(!refused.status.success());
	assert_eq!(
		stderr(&refused),
		"error: invalid account: local part is 65 characters; the maximum is 64 (RFC 5321)\n"
	);
	let refused = epistle(
		&[
			"account",
			"--config",
			&config,
			"add",
			"bob",
			"--address",
			"bob@example.com",
		],
		PASSWORD,
	);
	assert_eq!(
		stderr(&refused),
		"error: invalid account: example.com is not a domain this server handles\n"
	);
}

#[test]
fn alias_and_suppression_name_the_rule_an_address_breaks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let long = format!("team@{}.org", "x".repeat(64));
	let refused = epistle(
		&[
			"alias",
			"--config",
			&config,
			"add",
			&long,
			"alice@example.org",
		],
		b"",
	);
	assert!(!refused.status.success());
	assert_eq!(
		stderr(&refused),
		format!(
			"error: alias address: the domain label '{}\u{2026}' is 64 characters; the maximum is 63\n",
			"x".repeat(40)
		)
	);
	let refused = epistle(
		&["suppression", "--config", &config, "add", "a b@example.org"],
		b"",
	);
	assert!(!refused.status.success());
	assert_eq!(
		stderr(&refused),
		"error: cannot suppress: spaces are not allowed\n"
	);
}

fn stdout(output: &Output) -> String {
	String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_mixed_case_account_name_and_address_are_stored_in_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let added = epistle(
		&[
			"account-add",
			"--config",
			&config,
			"--name",
			"Alice",
			"--address",
			"Alice.Smith@Example.ORG",
		],
		PASSWORD,
	);
	assert!(added.status.success(), "{}", stderr(&added));
	assert_eq!(
		stderr(&added),
		"note: account name \"Alice\" is stored as \"alice\"\n"
	);
	let added = epistle(
		&[
			"account",
			"--config",
			&config,
			"add",
			"Bob",
			"--address",
			"Bob@Example.ORG",
		],
		PASSWORD,
	);
	assert!(added.status.success(), "{}", stderr(&added));
	assert_eq!(
		stderr(&added),
		"note: account name \"Bob\" is stored as \"bob\"\n"
	);

	// Every later command finds the account under any spelling.
	let address = epistle(
		&[
			"account",
			"--config",
			&config,
			"address",
			"add",
			"ALICE",
			"Smith@EXAMPLE.org",
		],
		b"",
	);
	assert!(address.status.success(), "{}", stderr(&address));
	let list = epistle(&["account", "--config", &config, "list"], b"");
	assert_eq!(
		stdout(&list),
		"alice\tdynamic\talice.smith@example.org,smith@example.org\n\
		 bob\tdynamic\tbob@example.org\n2 accounts\n"
	);
	let suppressed = epistle(
		&[
			"suppression",
			"--config",
			&config,
			"add",
			"Bounce@Elsewhere.Example",
			"--account",
			"Alice",
		],
		b"",
	);
	assert_eq!(
		stdout(&suppressed),
		"suppressed bounce@elsewhere.example for alice\n"
	);
}
