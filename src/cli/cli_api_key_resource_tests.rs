//! `epistle api-key list|create|revoke|rotate` against a real key store,
//! including keys bound to a static or a dynamic account.

use std::process::ExitCode;

use clap::Parser;

use crate::api::ApiKeyStore;
use crate::cli::Cli;

/// A data dir and a config with a static `postmaster` account.
fn setup() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	use std::io::Write as _;
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\
		 [[accounts]]\nname = \"postmaster\"\naddresses = [\"postmaster@example.org\"]\n",
		dir.path()
	)
	.expect("write config");
	(dir, file)
}

fn api_key(config: &tempfile::NamedTempFile, tail: &[&str]) -> ExitCode {
	let argv = ["epistle", "api-key", "--config"]
		.into_iter()
		.chain([config.path().to_str().expect("utf8 path")])
		.chain(tail.iter().copied());
	Cli::try_parse_from(argv).expect("parses").run()
}

fn labels(data_dir: &std::path::Path) -> Vec<String> {
	ApiKeyStore::open(data_dir)
		.expect("open key store")
		.list()
		.into_iter()
		.map(|key| key.label)
		.collect()
}

#[test]
fn list_json_prints_every_key_without_its_hash() {
	let (dir, config) = setup();
	let create = ["create", "ci", "--scope", "read", "--scope", "send"];
	assert_eq!(api_key(&config, &create), ExitCode::SUCCESS);
	let config_value = crate::config::Config::load(config.path()).expect("config");
	let mut out = Vec::new();
	let action = crate::cli::api_keys::ApiKeyCli::List { json: true };
	assert_eq!(
		crate::cli::api_keys::run(&config_value, action, &mut out),
		ExitCode::SUCCESS
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(
		value,
		serde_json::json!([{
			"label": "ci",
			"expires_at": null,
			"ip_cidr": null,
			"scopes": ["read", "send"],
			"domains": [],
			"account": null,
		}])
	);
	assert_eq!(labels(dir.path()), vec!["ci"]);
}

#[test]
fn revoke_removes_the_key_only_when_confirmed() {
	let (dir, config) = setup();
	assert_eq!(
		api_key(&config, &["create", "ci", "--scope", "read"]),
		ExitCode::SUCCESS
	);
	assert_eq!(api_key(&config, &["revoke", "ci"]), ExitCode::from(2));
	assert_eq!(labels(dir.path()), vec!["ci"], "revoked without --yes");
	assert_eq!(
		api_key(&config, &["revoke", "ci", "--yes"]),
		ExitCode::SUCCESS
	);
	assert!(
		labels(dir.path()).is_empty(),
		"key still stored after revoke"
	);
	assert_eq!(
		api_key(&config, &["revoke", "ci", "--yes"]),
		ExitCode::from(2)
	);
}

#[test]
fn a_static_account_can_hold_an_account_bound_key() {
	let (dir, config) = setup();
	let create = [
		"create",
		"mailer",
		"--scope",
		"send",
		"--account",
		"postmaster",
	];
	assert_eq!(api_key(&config, &create), ExitCode::SUCCESS);
	let keys = ApiKeyStore::open(dir.path()).expect("open").keys().to_vec();
	assert_eq!(keys.len(), 1);
	assert_eq!(keys[0].account.as_deref(), Some("postmaster"));
	assert_eq!(keys[0].scopes, vec!["send".to_string()]);
}

#[test]
fn an_unknown_account_gets_no_key() {
	let (dir, config) = setup();
	let create = ["create", "mailer", "--scope", "send", "--account", "ghost"];
	assert_eq!(api_key(&config, &create), ExitCode::from(2));
	assert!(labels(dir.path()).is_empty());
}

#[test]
fn an_account_bound_key_takes_no_domain_list() {
	let parsed = Cli::try_parse_from([
		"epistle",
		"api-key",
		"create",
		"mailer",
		"--scope",
		"send",
		"--account",
		"postmaster",
		"--domain",
		"example.org",
	]);
	let error = parsed.expect_err("--account with --domain must not parse");
	assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}
