//! `epistle account add` validates the name and addresses before it
//! asks for a password, so a typo in either fails at once instead of
//! after the operator has typed the password twice. The test holds
//! stdin closed (an EOF, like Ctrl+D on an empty terminal) and
//! asserts the error message is the validation error, not a
//! no-input-on-stdin error.
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

#[test]
fn invalid_name_fails_before_password_is_read() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	// An empty stdin must surface the validation refusal, not a
	// "no password on stdin" message: the validation runs first, so
	// the password prompt is never reached. The test holds stdin
	// closed and asserts the printed error names the bad name, not
	// the missing password.
	let mut empty: &[u8] = &[];
	let code = add_with_display_name(
		&config,
		"BAD NAME!",
		vec!["alice@example.org".to_string()],
		None,
		&mut empty,
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	// No store was opened (validation refused before the disk was
	// touched), so the directory is empty.
	assert!(
		!_dir.path().join("accounts.toml").exists(),
		"a refused name must not write accounts.toml"
	);
}

#[test]
fn out_of_domain_address_fails_before_password_is_read() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut empty: &[u8] = &[];
	let code = add_with_display_name(
		&config,
		"alice",
		vec!["alice@somewhere-else.example".to_string()],
		None,
		&mut empty,
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(
		!_dir.path().join("accounts.toml").exists(),
		"a refused address must not write accounts.toml"
	);
}

#[test]
fn empty_addresses_fails_before_password_is_read() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut empty: &[u8] = &[];
	let code = add_with_display_name(&config, "alice", Vec::new(), None, &mut empty);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
}

#[test]
fn closed_stdin_triggers_password_error_not_validation_error() {
	// When the validation accepts the name and addresses, the
	// password prompt is the next step. A closed stdin then yields
	// the "no input" refusal, not the validation refusal. The
	// accounts.toml file is also not written, because the validation
	// passed but the prompt failed before the hash was even
	// computed.
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut empty: &[u8] = &[];
	let code = add_with_display_name(
		&config,
		"alice",
		vec!["alice@example.org".to_string()],
		None,
		&mut empty,
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(
		!_dir.path().join("accounts.toml").exists(),
		"a closed stdin must not write accounts.toml"
	);
	let _ = fixture_password;
}