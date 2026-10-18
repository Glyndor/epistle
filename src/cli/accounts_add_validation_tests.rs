//! `epistle account add` checks the name and addresses before it asks
//! for a password, so a typo in either fails at once instead of after
//! the operator has typed the password twice. Each test offers a
//! password line on the input and asserts whether the command read it:
//! a refused name or address must leave it unread.
//!
//! Lives in a sibling so `accounts.rs` stays under the per-file
//! code-line budget.

use std::process::ExitCode;

use super::*;
use crate::config::Config;
use crate::smtp::auth::tests::fixture_password;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	std::io::Write::write_all(
		&mut file,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
			dir.path().canonicalize().expect("canonical")
		)
		.as_bytes(),
	)
	.expect("write config");
	(dir, file)
}

fn load(path: &std::path::Path) -> Config {
	Config::load(path).expect("config must load")
}

/// Run `account add` with a password line on the input. Returns the
/// exit code and whether the command read the line.
fn add_offering_a_password(
	config: &Config,
	name: &str,
	addresses: Vec<String>,
) -> (ExitCode, bool) {
	let line = format!("{}\n", fixture_password());
	let mut input = line.as_bytes();
	let code = add_with_display_name(
		config,
		name,
		addresses,
		None,
		&mut input,
		&mut std::io::sink(),
		false,
	);
	(code, input.len() < line.len())
}

#[test]
fn invalid_name_is_refused_before_the_password_is_read() {
	let (dir, file) = fixture("");
	let (code, read) = add_offering_a_password(
		&load(file.path()),
		"BAD NAME!",
		vec!["alice@example.org".to_string()],
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!read, "a refused name must not ask for the password");
	assert!(
		!dir.path().join("accounts.toml").exists(),
		"a refused name must not write accounts.toml"
	);
}

#[test]
fn out_of_domain_address_is_refused_before_the_password_is_read() {
	let (dir, file) = fixture("");
	let (code, read) = add_offering_a_password(
		&load(file.path()),
		"alice",
		vec!["alice@somewhere-else.example".to_string()],
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!read, "a refused address must not ask for the password");
	assert!(
		!dir.path().join("accounts.toml").exists(),
		"a refused address must not write accounts.toml"
	);
}

#[test]
fn no_address_is_refused_before_the_password_is_read() {
	let (_dir, file) = fixture("");
	let (code, read) = add_offering_a_password(&load(file.path()), "alice", Vec::new());
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!read, "an empty address list must not ask for the password");
}

#[test]
fn an_address_add_accepts_once_normalized_reaches_the_prompt() {
	// `add` trims and lowercases an address before it checks it, so the
	// early check must do the same or it refuses what `add` accepts.
	let (dir, file) = fixture("");
	let (code, read) = add_offering_a_password(
		&load(file.path()),
		"alice",
		vec![" Alice@EXAMPLE.ORG ".to_string()],
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(read, "an acceptable address must reach the password prompt");
	assert!(
		dir.path().join("accounts.toml").exists(),
		"the account must be written"
	);
}

/// The account name is a folder name and the address is RFC 5322: a dot is
/// refused in the first and fine in the second, and `account add` never
/// derives one from the other (that is `init`'s job).
#[test]
fn a_dotted_name_is_refused_before_the_password_is_read() {
	let (dir, file) = fixture("");
	let (code, read) = add_offering_a_password(
		&load(file.path()),
		"torre.control",
		vec!["torre.control@example.org".to_string()],
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!read, "a refused name must not ask for the password");
	assert!(
		!dir.path().join("accounts.toml").exists(),
		"a refused name must not write accounts.toml"
	);
}

#[test]
fn a_dotted_address_is_kept_for_an_account_with_a_hyphenated_name() {
	let (dir, file) = fixture("");
	let (code, read) = add_offering_a_password(
		&load(file.path()),
		"torre-control",
		vec!["Torre.Control@Example.ORG".to_string()],
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(read, "an acceptable name reaches the password prompt");
	let written = std::fs::read_to_string(dir.path().join("accounts.toml")).expect("accounts.toml");
	assert!(written.contains("name = \"torre-control\""), "{written}");
	assert!(
		written.contains("\"torre.control@example.org\""),
		"{written}"
	);
}
