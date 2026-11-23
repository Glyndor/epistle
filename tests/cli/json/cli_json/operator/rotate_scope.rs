//! `epistle rotate --accounts-only`: the recovery switch after a compromise
//! has to do what its name says. It resets the accounts and leaves every
//! other credential where it was, it asks before it does, and it is refused
//! next to `--all` or with nothing to go through.

use serde_json::Value;

use crate::harness::{Env, add_account, env, epistle};
use crate::snapshot::{changes, snapshot};

fn rotate(env: &Env, args: &[&str]) -> std::process::Output {
	let mut full = vec!["rotate"];
	full.extend_from_slice(args);
	full.extend_from_slice(&["--config", &env.config]);
	epistle(&full, b"")
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Two accounts, one API key and one app password.
fn populated() -> Env {
	let env = env("");
	add_account(&env, "alice");
	add_account(&env, "bob");
	let key = epistle(
		&[
			"api-key",
			"create",
			"ci",
			"--scope",
			"read",
			"--config",
			&env.config,
		],
		b"",
	);
	assert_eq!(key.status.code(), Some(0), "{}", stderr(&key));
	let app = epistle(
		&[
			"app-password",
			"create",
			"alice",
			"phone",
			"--config",
			&env.config,
		],
		b"",
	);
	assert_eq!(app.status.code(), Some(0), "{}", stderr(&app));
	env
}

#[test]
fn the_dry_run_lists_the_accounts_and_writes_nothing() {
	let env = populated();
	let before = snapshot(env.dir.path());
	let output = rotate(&env, &["--accounts-only", "--dry-run", "--json"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let plan: Value = serde_json::from_slice(&output.stdout).expect("JSON");
	assert_eq!(plan["dry_run"], Value::Bool(true));
	assert_eq!(plan["accounts"], serde_json::json!(["alice", "bob"]));
	assert_eq!(
		changes(&before, &snapshot(env.dir.path())),
		Vec::<String>::new()
	);
}

#[test]
fn without_yes_off_a_terminal_nothing_is_reset() {
	let env = populated();
	let before = snapshot(env.dir.path());
	let output = rotate(&env, &["--accounts-only"]);
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	assert!(
		stderr(&output).contains("was not confirmed"),
		"{}",
		stderr(&output)
	);
	// The run takes the rotation lock before it asks, and takes the file away
	// again when it is refused.
	assert_eq!(
		changes(&before, &snapshot(env.dir.path())),
		Vec::<String>::new()
	);
	let again = rotate(&env, &["--accounts-only", "--yes"]);
	assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
}

#[test]
fn accounts_only_resets_the_accounts_and_touches_no_other_credential() {
	let env = populated();
	let before = snapshot(env.dir.path());
	let output = rotate(&env, &["--accounts-only", "--yes"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let after = snapshot(env.dir.path());
	assert_ne!(
		after.get("data/accounts.toml"),
		before.get("data/accounts.toml"),
		"the accounts lost their passwords"
	);
	for (name, bytes) in &before {
		if name == "data/accounts.toml" {
			continue;
		}
		assert_eq!(
			after.get(name),
			Some(bytes),
			"{name} changed under `rotate --accounts-only`"
		);
	}
	let listed = epistle(&["api-key", "list", "--config", &env.config, "--json"], b"");
	assert!(String::from_utf8_lossy(&listed.stdout).contains("\"ci\""));
}

#[test]
fn it_is_refused_next_to_all_and_when_nothing_is_asked() {
	let env = populated();
	let before = snapshot(env.dir.path());
	let both = rotate(&env, &["--accounts-only", "--all", "--yes"]);
	assert_eq!(both.status.code(), Some(2));
	assert!(
		stderr(&both).contains("cannot be used with"),
		"{}",
		stderr(&both)
	);
	let neither = rotate(&env, &["--yes"]);
	assert_eq!(neither.status.code(), Some(2));
	assert!(
		stderr(&neither).contains("--accounts-only"),
		"{}",
		stderr(&neither)
	);
	let dry = rotate(&env, &["--dry-run"]);
	assert_eq!(dry.status.code(), Some(2));
	assert_eq!(
		changes(&before, &snapshot(env.dir.path())),
		Vec::<String>::new()
	);
}
