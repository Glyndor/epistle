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
	// The CLI validates the address before reading the password,
	// so the error names the account and the rule that broke.
	assert_eq!(
		stderr(&refused),
		"error: account bob: local part is 65 characters; the maximum is 64 (RFC 5321)\n"
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
		"error: account bob: example.com is not a domain this server handles\n"
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
		"note: the account name is stored in lowercase without surrounding spaces; use that form from now on\n"
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
		"note: the account name is stored in lowercase without surrounding spaces; use that form from now on\n"
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

#[test]
fn alias_add_and_edits_write_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let added = epistle(
		&[
			"alias",
			"--config",
			&config,
			"add",
			"Team@Example.ORG",
			"Alice@Example.ORG",
			"--sender",
			"Bob@Example.org",
		],
		b"",
	);
	assert!(added.status.success(), "{}", stderr(&added));
	let member = epistle(
		&[
			"alias",
			"--config",
			&config,
			"member",
			"add",
			"TEAM@example.org",
			"Carol@Example.ORG",
		],
		b"",
	);
	assert!(member.status.success(), "{}", stderr(&member));
	let list = epistle(&["alias", "--config", &config, "list", "--json"], b"");
	let rows: serde_json::Value = serde_json::from_slice(&list.stdout).expect("json");
	assert_eq!(rows[0]["address"], "team@example.org");
	assert_eq!(
		rows[0]["members"],
		serde_json::json!(["alice@example.org", "carol@example.org"])
	);
	assert_eq!(rows[0]["senders"], serde_json::json!(["bob@example.org"]));
	let file = std::fs::read_to_string(&config).expect("config");
	assert!(!file.contains("Example"), "{file}");
}

#[test]
fn a_hand_written_mixed_case_alias_is_edited_and_removed_by_any_spelling() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut file = std::fs::read_to_string(&config).expect("config");
	file.push_str(
		"\n[[alias]]\naddress = \"Team@Example.ORG\"\nmembers = [\"alice@example.org\"]\n",
	);
	std::fs::write(&config, file).expect("write");
	let member = epistle(
		&[
			"alias",
			"--config",
			&config,
			"member",
			"add",
			"team@example.org",
			"bob@example.org",
		],
		b"",
	);
	assert!(member.status.success(), "{}", stderr(&member));
	let after = std::fs::read_to_string(&config).expect("config");
	assert_eq!(after.matches("[[alias]]").count(), 1, "{after}");
	let removed = epistle(
		&[
			"alias",
			"--config",
			&config,
			"remove",
			"team@example.org",
			"--yes",
		],
		b"",
	);
	assert!(removed.status.success(), "{}", stderr(&removed));
	let after = std::fs::read_to_string(&config).expect("config");
	assert!(!after.contains("[[alias]]"), "{after}");
}

#[test]
fn domain_and_domain_alias_edits_write_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut file = std::fs::read_to_string(&config).expect("config");
	file.push_str("\n[domain_aliases]\n\"Old.Example\" = \"example.org\"\n");
	std::fs::write(&config, file).expect("write");
	let added = epistle(&["domain", "--config", &config, "add", "Example.NET"], b"");
	assert!(added.status.success(), "{}", stderr(&added));
	let aliased = epistle(
		&[
			"domain",
			"--config",
			&config,
			"alias",
			"add",
			"Alias.Example",
			"Example.NET",
		],
		b"",
	);
	assert!(aliased.status.success(), "{}", stderr(&aliased));
	let removed = epistle(
		&[
			"domain",
			"--config",
			&config,
			"alias",
			"remove",
			"old.example",
			"--yes",
		],
		b"",
	);
	assert!(removed.status.success(), "{}", stderr(&removed));
	let file = std::fs::read_to_string(&config).expect("config");
	assert!(
		file.contains("domains = [\"example.org\", \"example.net\"]"),
		"{file}"
	);
	assert!(
		file.contains("\"alias.example\" = \"example.net\""),
		"{file}"
	);
	assert!(!file.contains("Old.Example"), "{file}");
	assert!(!file.contains("NET") && !file.contains("Alias."), "{file}");
}
