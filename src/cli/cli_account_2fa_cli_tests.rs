//! `epistle account 2fa show|disable` driven through the parser and
//! `Cli::run`, asserting what the dynamic store holds afterwards.

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::base::{fixture_password, hash};

const SECRET: &str = "JBSWY3DPEHPK3PXP";

fn open_store(data_dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		data_dir,
		vec!["example.org".to_string()],
		Default::default(),
		Vec::new(),
	)
	.expect("open store")
}

/// A config over a fresh data dir holding `bob` with TOTP enrolled.
fn enrolled_bob() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	store
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..DynamicAccount::default()
		})
		.expect("add bob");
	store
		.set_totp("bob", Some(SECRET.to_string()))
		.expect("enrol");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	use std::io::Write as _;
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		dir.path()
	)
	.expect("write config");
	(dir, file)
}

fn cli(config: &tempfile::NamedTempFile, tail: &[&str]) -> Cli {
	let mut argv = vec![
		"epistle",
		"account",
		"--config",
		config.path().to_str().expect("utf8 path"),
	];
	argv.extend_from_slice(tail);
	Cli::try_parse_from(argv).expect("parses")
}

fn enrolled(data_dir: &std::path::Path) -> bool {
	open_store(data_dir)
		.dynamic_account("bob")
		.expect("bob exists")
		.totp_secret
		.is_some()
}

#[test]
fn account_2fa_parses_under_its_documented_name() {
	let parsed = Cli::try_parse_from(["epistle", "account", "2fa", "show", "bob"]);
	let cli = parsed.expect("`account 2fa show` parses");
	match cli.command {
		Command::Account { action, .. } => assert!(
			matches!(action, crate::cli::account::Subcommand::TwoFactor(_)),
			"`2fa` reached {action:?}"
		),
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn account_2fa_disable_with_yes_clears_the_secret() {
	let (dir, config) = enrolled_bob();
	assert!(enrolled(dir.path()));
	let code = cli(&config, &["2fa", "disable", "bob", "--yes"]).run();
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!enrolled(dir.path()), "secret still enrolled after disable");
}

#[test]
fn account_2fa_disable_without_yes_refuses_and_keeps_the_secret() {
	let (dir, config) = enrolled_bob();
	let code = cli(&config, &["2fa", "disable", "bob"]).run();
	assert_eq!(code, ExitCode::from(2));
	assert!(enrolled(dir.path()), "secret dropped without --yes");
}

#[test]
fn account_2fa_disable_answered_no_on_a_terminal_keeps_the_secret() {
	let (dir, config) = enrolled_bob();
	let command = cli(&config, &["2fa", "disable", "bob"]);
	let run = crate::cli::prompt::script::scripted(true, None, "n\n", || command.run());
	assert_eq!(run.value, ExitCode::from(2));
	assert!(run.stderr.contains("cancelled"), "stderr: {}", run.stderr);
	assert!(enrolled(dir.path()), "secret dropped after answering no");
}

#[test]
fn account_2fa_disable_answered_yes_on_a_terminal_clears_the_secret() {
	let (dir, config) = enrolled_bob();
	let command = cli(&config, &["2fa", "disable", "bob"]);
	let run = crate::cli::prompt::script::scripted(true, None, "y\n", || command.run());
	assert_eq!(run.value, ExitCode::SUCCESS);
	assert!(
		run.stderr.contains("TOTP"),
		"question not asked: {}",
		run.stderr
	);
	assert!(!enrolled(dir.path()), "secret still enrolled after yes");
}
