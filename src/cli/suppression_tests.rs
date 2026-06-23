//! Tests for the `mail suppression` command.

use super::*;
use crate::queue::SuppressionList;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

#[test]
fn lists_and_removes_suppressed_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	SuppressionList::open(dir.path())
		.expect("open")
		.suppress("bob@example.net");

	// List shows the suppressed address.
	let mut out = Vec::new();
	assert_eq!(run(&config, None, None, &mut out), ExitCode::SUCCESS);
	assert_eq!(String::from_utf8(out).expect("utf8"), "bob@example.net\n");

	// Remove clears it.
	let mut out = Vec::new();
	assert_eq!(
		run(&config, Some("bob@example.net"), None, &mut out),
		ExitCode::SUCCESS
	);
	assert!(
		!SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}

#[test]
fn lists_and_removes_per_account_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	SuppressionList::open(dir.path())
		.expect("open")
		.suppress_for("alice@example.org", "bob@example.net");

	// The global list is empty; the per-account list shows the address.
	let mut out = Vec::new();
	assert_eq!(run(&config, None, None, &mut out), ExitCode::SUCCESS);
	assert!(out.is_empty());

	let mut out = Vec::new();
	assert_eq!(
		run(&config, None, Some("alice@example.org"), &mut out),
		ExitCode::SUCCESS
	);
	assert_eq!(String::from_utf8(out).expect("utf8"), "bob@example.net\n");

	// Remove scoped to the account clears it.
	let mut out = Vec::new();
	assert_eq!(
		run(
			&config,
			Some("bob@example.net"),
			Some("alice@example.org"),
			&mut out
		),
		ExitCode::SUCCESS
	);
	assert!(
		!SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed_for("alice@example.org", "bob@example.net")
	);
}
