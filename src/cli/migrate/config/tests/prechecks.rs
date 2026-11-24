//! What an import checks before it writes: a password file that cannot be
//! made, or a key file that holds another key, refuse the whole import and
//! leave the configuration, the accounts and the key directory as they were,
//! so the same command works once the cause is gone.

use std::path::{Path, PathBuf};

use clap::Parser;

use super::super::super::{MigrateArgs, MigrateCli};
use super::*;
use crate::cli::{Cli, Command};

fn epistle(dir: &Path) -> PathBuf {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data");
	let file = dir.join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.new.example\"\ndata_dir = \"{}\"\ndomains = []\n",
			data.display()
		),
	)
	.expect("config");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	file
}

/// The import of the Mox fixture with `passwords_out`, run the way the
/// command runs it.
fn run_import(config: &Path, source: &Path, passwords_out: &Path) -> (ExitCode, bool) {
	let argv = [
		"epistle",
		"migrate",
		"mox",
		"--from",
		source.to_str().expect("utf-8"),
		"--passwords-out",
		passwords_out.to_str().expect("utf-8"),
	];
	let Command::Migrate(MigrateArgs {
		action: MigrateCli::Mox { from, import: args },
		..
	}) = Cli::try_parse_from(argv).expect("parse").command
	else {
		unreachable!("parsed as migrate mox");
	};
	import(
		config,
		crate::migrate::mox::read(&from).map_err(|error| error.to_string()),
		&args,
		&mut Vec::new(),
	)
}

fn source(dir: &Path) -> PathBuf {
	let source = dir.join("mox");
	std::fs::create_dir_all(&source).expect("mox dir");
	crate::migrate::mox::fixture::write(&source);
	source
}

/// Nothing the import writes exists: no account store, no key directory.
fn nothing_written(dir: &Path) {
	assert!(
		!dir.join("data/accounts.toml").exists(),
		"an account was made"
	);
	assert!(
		!dir.join("data/dkim-migrated").exists(),
		"a key was written"
	);
}

#[test]
fn a_password_file_that_exists_refuses_before_the_configuration_is_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let source = source(dir.path());
	let before = std::fs::read(&config).expect("read");
	let taken = dir.path().join("passwords");
	std::fs::write(&taken, "taken\n").expect("file");

	let (code, changed) = run_import(&config, &source, &taken);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!changed);
	assert_eq!(std::fs::read(&config).expect("read"), before);
	assert_eq!(std::fs::read_to_string(&taken).expect("file"), "taken\n");
	nothing_written(dir.path());

	// Once the file is out of the way the same import goes through, with
	// no `--merge`: nothing was half done.
	let fresh = dir.path().join("fresh");
	let (code, changed) = run_import(&config, &source, &fresh);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(changed);
	assert_eq!(
		std::fs::read_to_string(&fresh)
			.expect("passwords")
			.lines()
			.count(),
		2
	);
}

#[test]
fn a_password_file_in_a_directory_that_is_not_there_refuses_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let source = source(dir.path());
	let before = std::fs::read(&config).expect("read");
	let nowhere = dir.path().join("missing/passwords");

	let (code, changed) = run_import(&config, &source, &nowhere);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!changed);
	assert_eq!(std::fs::read(&config).expect("read"), before);
	nothing_written(dir.path());
	assert!(!nowhere.exists());
}

#[test]
fn a_key_file_with_another_key_refuses_before_anything_is_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let source = source(dir.path());
	let before = std::fs::read(&config).expect("read");
	let keys = dir.path().join("data/dkim-migrated/example.com");
	std::fs::create_dir_all(&keys).expect("key dir");
	std::fs::write(keys.join("2024a.ed25519.pem"), "another key\n").expect("key");
	let passwords = dir.path().join("passwords");

	let (code, changed) = run_import(&config, &source, &passwords);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!changed);
	assert_eq!(std::fs::read(&config).expect("read"), before);
	assert!(
		!passwords.exists(),
		"no password file for an import that did not happen"
	);
	assert!(!dir.path().join("data/accounts.toml").exists());
	assert_eq!(
		std::fs::read_to_string(keys.join("2024a.ed25519.pem")).expect("key"),
		"another key\n"
	);
}

#[test]
fn a_configuration_that_cannot_be_written_leaves_no_password_file() {
	use std::os::unix::fs::PermissionsExt;
	// Mode bits do not stop root, and then the write below succeeds.
	// SAFETY: geteuid takes no arguments and cannot fail.
	if unsafe { libc::geteuid() } == 0 {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let source = source(dir.path());
	// The configuration is replaced by writing next to it, so a directory
	// that cannot be written makes the commit fail after the checks passed.
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).expect("chmod");
	// The password file lives where it can still be made.
	let outside = tempfile::tempdir().expect("tempdir");
	let passwords_out = outside.path().join("passwords");
	let (code, changed) = run_import(&config, &source, &passwords_out);
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
	assert_ne!(code, ExitCode::SUCCESS);
	assert!(!changed);
	assert!(!passwords_out.exists(), "a password file was left behind");
}
