//! `epistle account forward add|remove` through `Cli::run`, checking what
//! the dynamic store and the rebuilt directory hold afterwards.

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;
use crate::directory_store::{AccountStore, DynamicAccount};

const WITH_SRS: &str = "srs_secret = \"a shared srs secret\"\n";

/// A data dir with dynamic `bob`, and a config serving `example.org`
/// with `extra` appended to its top-level keys.
fn setup(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	use std::io::Write as _;
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}",
		dir.path()
	)
	.expect("write config");
	open_store(dir.path())
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: crate::smtp::auth::tests::hash(
				crate::smtp::auth::tests::fixture_password(),
			),
			..DynamicAccount::default()
		})
		.expect("add bob");
	(dir, file)
}

fn open_store(data_dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		data_dir,
		vec!["example.org".to_string()],
		Default::default(),
		Vec::new(),
	)
	.expect("open store")
}

fn forward(config: &tempfile::NamedTempFile, verb: &str, address: &str) -> ExitCode {
	Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		config.path().to_str().expect("utf8 path"),
		"forward",
		verb,
		"bob",
		address,
	])
	.expect("parses")
	.run()
}

/// The forward targets the directory hands delivery for bob.
fn delivered_forwards(data_dir: &std::path::Path) -> Vec<String> {
	let store = open_store(data_dir);
	let directory = store.handle().current();
	directory
		.forwards("bob")
		.map(|(targets, _)| targets.to_vec())
		.unwrap_or_default()
}

#[test]
fn forward_add_reaches_the_directory_delivery_reads() {
	let (dir, config) = setup(WITH_SRS);
	assert_eq!(
		forward(&config, "add", "out@example.com"),
		ExitCode::SUCCESS
	);
	assert_eq!(delivered_forwards(dir.path()), vec!["out@example.com"]);
	assert_eq!(
		forward(&config, "remove", "out@example.com"),
		ExitCode::SUCCESS
	);
	assert!(delivered_forwards(dir.path()).is_empty());
}

#[test]
fn forward_add_without_srs_secret_is_refused() {
	let (dir, config) = setup("");
	assert_ne!(
		forward(&config, "add", "out@example.com"),
		ExitCode::SUCCESS
	);
	assert!(open_store(dir.path()).forwards("bob").is_empty());
}

#[test]
fn forward_add_to_the_account_itself_is_refused() {
	let (dir, config) = setup(WITH_SRS);
	assert_ne!(
		forward(&config, "add", "BOB@example.org"),
		ExitCode::SUCCESS
	);
	assert!(open_store(dir.path()).forwards("bob").is_empty());
}

#[test]
fn forward_add_of_an_invalid_address_is_refused() {
	let (dir, config) = setup(WITH_SRS);
	assert_ne!(forward(&config, "add", "not an address"), ExitCode::SUCCESS);
	assert!(open_store(dir.path()).forwards("bob").is_empty());
}
