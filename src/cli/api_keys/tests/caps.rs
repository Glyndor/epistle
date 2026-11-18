//! `epistle api-key create --account` and the cap on API keys per account.

use super::*;
use crate::api::ApiKeyStore;

fn config(data_dir: &std::path::Path, limits: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n{limits}\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn make(config: &Config, label: &str, account: Option<&str>) -> ExitCode {
	create(
		config,
		NewKey {
			label: label.to_string(),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string()],
			domains: Vec::new(),
			account: account.map(str::to_string),
			class: None,
			auto_submitted: false,
		},
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
}

#[test]
fn the_command_stops_at_the_cap_and_leaves_administrative_keys_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "[limits]\nmax_api_keys_per_account = 1");
	assert_eq!(make(&config, "mine", Some("alice")), ExitCode::SUCCESS);
	assert_eq!(
		make(&config, "second", Some("alice")),
		ExitCode::from(crate::cli::exit::POLICY)
	);
	assert_eq!(make(&config, "admin", None), ExitCode::SUCCESS);
	assert_eq!(make(&config, "admin2", None), ExitCode::SUCCESS);
	let labels: Vec<String> = ApiKeyStore::open(dir.path())
		.expect("open")
		.keys()
		.iter()
		.map(|key| key.label.clone())
		.collect();
	assert_eq!(labels, ["mine", "admin", "admin2"]);
}

#[test]
fn without_a_cap_the_command_keeps_creating() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	for label in ["a", "b", "c"] {
		assert_eq!(make(&config, label, Some("alice")), ExitCode::SUCCESS);
	}
}
