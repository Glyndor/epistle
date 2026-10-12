//! The 0/1/2 split: a refusal (fix the command) against an operation
//! failure (retry later), for the store errors and through `Cli::run`.

use std::process::ExitCode;

use clap::Parser;

use super::*;

#[test]
fn store_refusals_are_two_and_io_failures_are_one() {
	for refusal in [
		StoreError::NotFound("bob".into()),
		StoreError::Duplicate("bob".into()),
		StoreError::Invalid("bad".into()),
		StoreError::LimitReached { max: 1 },
	] {
		assert_eq!(for_store_error(&refusal), ExitCode::from(2), "{refusal:?}");
	}
	let io = StoreError::Io(std::io::Error::other("disk on fire"));
	assert_eq!(for_store_error(&io), ExitCode::FAILURE);
	let gone = std::io::Error::new(std::io::ErrorKind::NotFound, "no such key");
	assert_eq!(for_io_error(&gone), ExitCode::from(2));
	let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
	assert_eq!(for_io_error(&denied), ExitCode::FAILURE);
}

/// `account disable <name>` on a data dir whose store is readable but
/// does not know the name, and on one whose store cannot be parsed.
#[test]
fn an_unknown_name_is_two_and_an_unreadable_store_is_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	use std::io::Write as _;
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		dir.path()
	)
	.expect("write config");
	let disable = || {
		crate::cli::Cli::try_parse_from([
			"epistle",
			"account",
			"--config",
			file.path().to_str().expect("utf8 path"),
			"disable",
			"ghost",
		])
		.expect("parses")
		.run()
	};
	assert_eq!(disable(), ExitCode::from(2));
	std::fs::write(dir.path().join("accounts.toml"), "[[accounts]\nnot toml").expect("corrupt");
	assert_eq!(disable(), ExitCode::FAILURE);
}
