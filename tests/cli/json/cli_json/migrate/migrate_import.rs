//! `epistle migrate mox` and `epistle migrate stalwart` against a throwaway
//! configuration: how the imported accounts get their password, and what the
//! import leaves behind.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::harness::{Env, env, epistle};

pub const MOX_CONF: &str = "DataDir: ../data\nHostname: mail.new.example\n";

pub const DOMAINS_CONF: &str = "\
Domains:
	moved.example:
		Description: the domain that moves
Accounts:
	alice:
		Domain: moved.example
		Destinations:
			alice@moved.example: nil
";

/// A Mox configuration directory next to the data directory.
pub fn mox_source(env: &Env) -> PathBuf {
	let dir = env.dir.path().join("mox");
	std::fs::create_dir_all(&dir).expect("mox dir");
	std::fs::write(dir.join("mox.conf"), MOX_CONF).expect("mox.conf");
	std::fs::write(dir.join("domains.conf"), DOMAINS_CONF).expect("domains.conf");
	dir
}

pub fn migrate(env: &Env, source: &Path, extra: &[&str]) -> std::process::Output {
	let mut args = vec![
		"migrate",
		"--config",
		env.config.as_str(),
		"mox",
		"--from",
		source.to_str().expect("utf-8"),
	];
	args.extend_from_slice(extra);
	epistle(&args, b"")
}

pub fn stdout(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The names `account list --json` shows.
pub fn accounts(env: &Env) -> Vec<String> {
	let output = epistle(&["account", "list", "--config", &env.config, "--json"], b"");
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let listed: Value = serde_json::from_slice(&output.stdout).expect("a JSON array");
	listed
		.as_array()
		.expect("array")
		.iter()
		.map(|row| row["name"].as_str().expect("name").to_string())
		.collect()
}

/// `account show NAME --json`.
pub fn account(env: &Env, name: &str) -> Value {
	let output = epistle(
		&["account", "show", name, "--config", &env.config, "--json"],
		b"",
	);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	serde_json::from_slice(&output.stdout).expect("a JSON object")
}

pub fn configured_domains(env: &Env) -> String {
	std::fs::read_to_string(&env.config).expect("config")
}

#[test]
fn password_reset_creates_disabled_accounts_nobody_holds_a_password_for() {
	let env = env("");
	let source = mox_source(&env);
	let output = migrate(&env, &source, &["--password-reset"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let text = stdout(&output);
	assert!(text.contains("accounts added: alice"), "{text}");
	assert!(text.contains("no known password"), "{text}");
	assert!(!text.contains("temporary passwords are in"), "{text}");
	assert_eq!(accounts(&env), ["alice"]);
	assert_eq!(account(&env, "alice")["disabled"], Value::Bool(true));
	assert!(configured_domains(&env).contains("moved.example"));
	let created: Vec<_> = std::fs::read_dir(env.dir.path())
		.expect("dir")
		.map(|entry| entry.expect("entry").file_name())
		.collect();
	assert!(
		created.iter().all(|name| name != "passwords"),
		"no password file is written: {created:?}"
	);
}

#[test]
fn passwords_out_writes_a_private_file_with_the_temporary_passwords() {
	use std::os::unix::fs::PermissionsExt;
	let env = env("");
	let source = mox_source(&env);
	let file = env.dir.path().join("passwords");
	let output = migrate(
		&env,
		&source,
		&["--passwords-out", file.to_str().expect("utf-8")],
	);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let text = std::fs::read_to_string(&file).expect("password file");
	let (name, secret) = text.trim_end().split_once('\t').expect("name and secret");
	assert_eq!(name, "alice");
	assert_eq!(secret.len(), 32);
	assert_eq!(
		std::fs::metadata(&file)
			.expect("metadata")
			.permissions()
			.mode()
			& 0o777,
		0o600
	);
	let shown = stdout(&output);
	assert!(shown.contains("temporary passwords are in"), "{shown}");
	assert!(!shown.contains(secret), "the secret stays out of stdout");
	assert!(
		!stderr(&output).contains(secret),
		"the secret stays out of stderr"
	);
	assert_eq!(accounts(&env), ["alice"]);
	assert_eq!(account(&env, "alice")["disabled"], Value::Bool(true));
}

#[test]
fn a_password_choice_is_needed_unless_it_is_a_dry_run() {
	let env = env("");
	let source = mox_source(&env);
	let before = configured_domains(&env);
	let output = migrate(&env, &source, &[]);
	assert_eq!(output.status.code(), Some(2));
	assert!(stdout(&output).is_empty());
	assert!(
		stderr(&output).contains("--passwords-out"),
		"{}",
		stderr(&output)
	);
	assert_eq!(configured_domains(&env), before);
	assert!(accounts(&env).is_empty());

	let dry = migrate(&env, &source, &["--dry-run"]);
	assert_eq!(dry.status.code(), Some(0), "{}", stderr(&dry));
	assert!(
		stdout(&dry).contains("accounts would add: alice"),
		"{}",
		stdout(&dry)
	);
	assert_eq!(configured_domains(&env), before);
	assert!(accounts(&env).is_empty());
}

#[test]
fn the_two_password_choices_exclude_each_other_and_write_nothing() {
	let env = env("");
	let source = mox_source(&env);
	let before = configured_domains(&env);
	let file = env.dir.path().join("passwords");
	let output = migrate(
		&env,
		&source,
		&[
			"--password-reset",
			"--passwords-out",
			file.to_str().expect("utf-8"),
		],
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(
		stderr(&output).contains("cannot be used with"),
		"{}",
		stderr(&output)
	);
	assert!(!file.exists());
	assert_eq!(configured_domains(&env), before);
	assert!(accounts(&env).is_empty());
}
