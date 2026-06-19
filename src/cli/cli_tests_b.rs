//! CLI command-dispatch tests (Cli::run over real temp configs).

use super::*;
use std::io::Write;

fn config_at(data_dir: &std::path::Path) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		data_dir
	)
	.expect("write");
	file
}

fn run(args: &[&str]) -> ExitCode {
	Cli::try_parse_from(args).expect("parses").run()
}

#[test]
fn export_dispatch_succeeds_for_existing_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let cfg = config_at(dir.path());
	let path = cfg.path().to_str().expect("utf8");
	assert_eq!(
		run(&["mail", "export", "--config", path, "--account", "alice"]),
		ExitCode::SUCCESS
	);
}

#[test]
fn queue_dispatch_succeeds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let path = cfg.path().to_str().expect("utf8");
	assert_eq!(run(&["mail", "queue", "--config", path]), ExitCode::SUCCESS);
}

#[test]
fn accounts_dispatch_succeeds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let path = cfg.path().to_str().expect("utf8");
	assert_eq!(
		run(&["mail", "accounts", "--config", path]),
		ExitCode::SUCCESS
	);
}

#[test]
fn dispatch_reports_config_load_failure() {
	// A nonexistent config file makes every config-taking command fail.
	for args in [
		vec!["mail", "export", "--config", "/nope.toml", "--account", "a"],
		vec!["mail", "queue", "--config", "/nope.toml"],
		vec!["mail", "accounts", "--config", "/nope.toml"],
		vec!["mail", "config-check", "--config", "/nope.toml"],
	] {
		assert_eq!(run(&args), ExitCode::FAILURE, "{args:?}");
	}
}
