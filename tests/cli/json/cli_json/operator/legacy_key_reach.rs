//! What the hidden `api-key-create` and `app-password-create` commands store,
//! read back from the files they write: the alias takes `--account` together
//! with `--domain`, which the resource form refuses, so this pins how far the
//! key it makes reaches.

use serde_json::Value;

use epistle::api::{ApiKeySet, Principal};

use crate::harness::{Env, add_account, env, epistle};

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

fn flat_key(env: &Env, extra: &[&str]) -> std::process::Output {
	let mut args = vec![
		"api-key-create",
		"--config",
		env.config.as_str(),
		"--label",
		"ci",
		"--scope",
		"read",
	];
	args.extend_from_slice(extra);
	epistle(&args, b"")
}

fn stored(env: &Env) -> Vec<epistle::api::ApiKey> {
	let set = ApiKeySet::open(&env.data_dir()).expect("api_keys.toml");
	set.snapshot().to_vec()
}

#[test]
fn the_flat_command_takes_an_account_and_a_domain_that_the_resource_form_refuses() {
	let env = env("");
	add_account(&env, "alice");
	let output = epistle(
		&[
			"api-key",
			"create",
			"ci",
			"--config",
			&env.config,
			"--scope",
			"read",
			"--account",
			"alice",
			"--domain",
			"example.org",
		],
		b"",
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(
		stderr(&output).contains("cannot be used with"),
		"{}",
		stderr(&output)
	);
	assert!(stored(&env).is_empty());

	let output = flat_key(&env, &["--account", "alice", "--domain", "example.org"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let keys = stored(&env);
	assert_eq!(keys.len(), 1);
	assert_eq!(keys[0].account.as_deref(), Some("alice"));
	assert_eq!(keys[0].domains, ["example.org"]);
}

#[test]
fn a_flat_key_with_an_account_and_a_domain_is_confined_by_both() {
	let env = env("");
	add_account(&env, "alice");
	add_account(&env, "bob");
	let output = flat_key(&env, &["--account", "alice", "--domain", "example.org"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let keys = stored(&env);
	let principal = Principal::of_key(&keys[0], None);
	assert!(!principal.is_unrestricted());
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(!principal.admits_account("bob", &["bob@example.org".into()]));
	assert!(
		!principal.admits_account("alice", &["alice@elsewhere.example".into()]),
		"the domain list narrows the account it is bound to"
	);
	// An account-bound key has no domain-wide reach.
	assert!(!principal.admits_addresses(&["x@example.org".into()]));
}

#[test]
fn the_flat_command_confines_a_key_to_the_domains_it_names() {
	let env = env("");
	let output = flat_key(
		&env,
		&["--domain", "example.org", "--ip-cidr", "203.0.113.0/24"],
	);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let keys = stored(&env);
	assert_eq!(keys[0].ip_cidr.as_deref(), Some("203.0.113.0/24"));
	let principal = Principal::of_key(&keys[0], None);
	assert!(principal.admits_domain("example.org"));
	assert!(!principal.admits_domain("example.net"));
	assert!(!principal.is_unrestricted());
}

#[test]
fn the_flat_command_refuses_what_the_resource_form_refuses() {
	let env = env("");
	add_account(&env, "alice");
	for extra in [
		&["--ip-cidr", "not-a-network"][..],
		&["--account", "nobody"][..],
		&["--account", "alice", "--scope", "scim"][..],
	] {
		let flat = flat_key(&env, extra);
		let mut canonical = vec![
			"api-key",
			"create",
			"ci",
			"--config",
			env.config.as_str(),
			"--scope",
			"read",
		];
		canonical.extend_from_slice(extra);
		let resource = epistle(&canonical, b"");
		assert_ne!(flat.status.code(), Some(0), "{extra:?}");
		assert_eq!(flat.status.code(), resource.status.code(), "{extra:?}");
		assert!(stored(&env).is_empty(), "{extra:?}");
	}
}

#[test]
fn the_flat_command_without_a_scope_is_refused() {
	let env = env("");
	let output = epistle(
		&["api-key-create", "--config", &env.config, "--label", "ci"],
		b"",
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(
		stderr(&output).contains("--scope is required"),
		"{}",
		stderr(&output)
	);
	assert!(stored(&env).is_empty());
}

/// The app passwords as `app-password list --json` prints them.
fn app_passwords(env: &Env) -> Vec<Value> {
	let output = epistle(
		&["app-password", "list", "--config", &env.config, "--json"],
		b"",
	);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let listed: Value = serde_json::from_slice(&output.stdout).expect("a JSON array");
	listed.as_array().expect("array").clone()
}

/// The `save_sent` override of the app password `label`.
fn save_sent(env: &Env, label: &str) -> Value {
	app_passwords(env)
		.into_iter()
		.find(|row| row["label"] == label)
		.expect("the app password is listed")["save_sent"]
		.clone()
}

#[test]
fn the_flat_app_password_command_keeps_the_save_sent_override() {
	let env = env("");
	add_account(&env, "alice");
	for (state, shown) in [("off", false), ("on", true)] {
		let label = format!("phone-{state}");
		let output = epistle(
			&[
				"app-password-create",
				"--config",
				&env.config,
				"--account",
				"alice",
				"--label",
				&label,
				"--save-sent",
				state,
			],
			b"",
		);
		assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
		assert_eq!(save_sent(&env, &label), Value::from(shown), "{state}");
	}
	let output = epistle(
		&[
			"app-password-create",
			"--config",
			&env.config,
			"--account",
			"alice",
			"--label",
			"tablet",
			"--save-sent",
			"sometimes",
		],
		b"",
	);
	assert_ne!(output.status.code(), Some(0));
	assert!(output.status.code().is_some());
	assert!(
		app_passwords(&env)
			.iter()
			.all(|row| row["label"] != "tablet")
	);
}
