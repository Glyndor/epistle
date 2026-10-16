//! The hidden flat commands that old scripts still call take `--json` and
//! print what the resource form prints, so a script moves to the new
//! names without changing how it reads the result.

use serde_json::{Value, json};

use crate::harness::{Env, PASSWORD, add_account, env, epistle, json};

/// Run `args` with `--config` and `--json`, stdin carrying the password.
fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = args.to_vec();
	full.extend_from_slice(&["--config", &env.config, "--json"]);
	json(&epistle(&full, PASSWORD))
}

/// Run the flat command `flat` in one fresh environment and the resource
/// command `resource` in another, both prepared by `prepare`, and return
/// the two results.
fn both(prepare: impl Fn(&Env), flat: &[&str], resource: &[&str]) -> ((i32, Value), (i32, Value)) {
	let first = env("");
	prepare(&first);
	let second = env("");
	prepare(&second);
	(run(&first, flat), run(&second, resource))
}

/// `value` without the one-time secret the command minted.
fn without(mut value: Value, key: &str) -> Value {
	value[key] = Value::Null;
	value
}

#[test]
fn accounts_lists_like_account_list() {
	let (flat, resource) = both(
		|e| add_account(e, "bob"),
		&["accounts"],
		&["account", "list"],
	);
	assert_eq!(flat.0, 0);
	assert_eq!(flat.1[0]["name"], "bob");
	assert_eq!(flat, resource);
}

#[test]
fn account_add_prints_the_new_account() {
	let (flat, resource) = both(
		|_| {},
		&[
			"account-add",
			"--name",
			"bob",
			"--address",
			"bob@example.org",
		],
		&["account", "add", "bob", "--address", "bob@example.org"],
	);
	assert_eq!(
		flat,
		(
			0,
			json!({
				"result": "saved", "action": "add", "account": "bob",
				"addresses": ["bob@example.org"], "display_name": null, "reload": "no-server",
			})
		)
	);
	assert_eq!(flat, resource);
}

#[test]
fn account_remove_reports_what_went() {
	let (flat, resource) = both(
		|e| add_account(e, "bob"),
		&[
			"account-remove",
			"--name",
			"bob",
			"--queue",
			"drain",
			"--yes",
		],
		&["account", "remove", "bob", "--queue", "drain", "--yes"],
	);
	assert_eq!(flat.0, 0);
	assert_eq!(flat.1["action"], "remove");
	assert_eq!(flat.1["account"], "bob");
	assert_eq!(flat, resource);
}

#[test]
fn app_password_flat_commands_match_the_resource_form() {
	let flat_env = env("");
	add_account(&flat_env, "bob");
	let (code, created) = run(
		&flat_env,
		&[
			"app-password-create",
			"--account",
			"bob",
			"--label",
			"phone",
		],
	);
	assert_eq!(code, 0);
	let secret = created["secret"].as_str().expect("secret").to_string();
	assert_eq!(
		secret.len(),
		52,
		"the secret is not the length the form prints"
	);
	assert_eq!(
		without(created, "secret"),
		json!({
			"result": "saved", "action": "create", "account": "bob", "label": "phone",
			"expires_at": null, "ip_cidr": null, "save_sent": null, "secret": null,
		})
	);

	let (code, listed) = run(&flat_env, &["app-passwords"]);
	assert_eq!(code, 0);
	assert_eq!(listed[0]["label"], "phone");
	assert!(
		!listed.to_string().contains(&secret),
		"the list printed the secret"
	);

	let (code, revoked) = run(
		&flat_env,
		&[
			"app-password-revoke",
			"--account",
			"bob",
			"--label",
			"phone",
			"--yes",
		],
	);
	assert_eq!(code, 0);
	assert_eq!(
		revoked,
		json!({"result": "saved", "action": "revoke", "account": "bob", "label": "phone"})
	);
	assert_eq!(run(&flat_env, &["app-passwords"]), (0, json!([])));
}

#[test]
fn api_key_flat_commands_match_the_resource_form() {
	let flat_env = env("");
	let (code, created) = run(
		&flat_env,
		&["api-key-create", "--label", "ci", "--scope", "read"],
	);
	assert_eq!(code, 0);
	let key = created["key"].as_str().expect("key").to_string();
	assert_eq!(key.len(), 52, "the key is not the length the form prints");
	assert_eq!(
		without(created, "key"),
		json!({
			"result": "saved", "action": "create", "label": "ci", "scopes": ["read"],
			"domains": [], "account": null, "expires_at": null, "ip_cidr": null, "key": null,
		})
	);

	let (code, listed) = run(&flat_env, &["api-keys"]);
	assert_eq!(code, 0);
	assert_eq!(listed[0]["label"], "ci");
	assert!(
		!listed.to_string().contains(&key),
		"the list printed the key"
	);

	let (code, revoked) = run(&flat_env, &["api-key-revoke", "--label", "ci", "--yes"]);
	assert_eq!(code, 0);
	assert_eq!(
		revoked,
		json!({"result": "saved", "action": "revoke", "label": "ci"})
	);
	assert_eq!(run(&flat_env, &["api-keys"]), (0, json!([])));
}

#[test]
fn a_flat_refusal_prints_nothing_on_stdout() {
	let env = env("");
	let output = epistle(
		&[
			"account-remove",
			"--name",
			"nobody",
			"--queue",
			"drain",
			"--yes",
			"--config",
			&env.config,
			"--json",
		],
		b"",
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(
		output.stdout.is_empty(),
		"stdout: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stderr),
		"error: no such account: nobody\n"
	);
}
