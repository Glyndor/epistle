//! `epistle app-password create` and the cap on app passwords per account.

use crate::cli::app::passwords::tests::*;
use crate::directory_store::AppPasswordStore;

fn config(data_dir: &std::path::Path, limits: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n{limits}",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn make(config: &Config, label: &str) -> ExitCode {
	create(
		config,
		"alice",
		label,
		None,
		None,
		None,
		None,
		false,
		&mut Vec::new(),
	)
}

#[test]
fn the_command_stops_at_the_cap_with_a_policy_exit_and_creates_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(
		dir.path().join("accounts.toml"),
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"stub\"\n",
	)
	.expect("accounts.toml");
	let config = config(dir.path(), "[limits]\nmax_app_passwords_per_account = 1\n");
	assert_eq!(make(&config, "phone"), ExitCode::SUCCESS);
	assert_eq!(
		make(&config, "laptop"),
		ExitCode::from(crate::cli::exit::POLICY)
	);
	let held = AppPasswordStore::open(dir.path()).expect("open");
	assert_eq!(held.for_account("alice").len(), 1);
}

#[test]
fn without_a_cap_the_command_keeps_creating() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(
		dir.path().join("accounts.toml"),
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"stub\"\n",
	)
	.expect("accounts.toml");
	let config = config(dir.path(), "");
	for label in ["a", "b", "c"] {
		assert_eq!(make(&config, label), ExitCode::SUCCESS);
	}
}
