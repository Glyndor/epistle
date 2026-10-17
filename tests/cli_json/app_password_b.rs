//! `app-password rotate` and `app-password rename`, and the label rules.

use serde_json::{Value, json};

use epistle::directory_store::AppPasswordStore;
use epistle::password::Policy;

use crate::harness::{Env, add_account, env, epistle as run_epistle, json};

const FAR_FUTURE: u64 = 4_102_444_800;
const NOW: u64 = 1_800_000_000;

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["app-password"];
	full.extend_from_slice(args);
	full.extend(["--config", &env.config, "--json"]);
	json(&run_epistle(&full, b""))
}

fn plain(env: &Env, args: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["app-password"];
	full.extend_from_slice(args);
	full.extend(["--config", &env.config]);
	let output = run_epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

/// A phone credential with every optional setting, and its secret.
fn phone(env: &Env) -> String {
	add_account(env, "bob");
	let (code, created) = run(
		env,
		&[
			"create",
			"bob",
			"phone",
			"--ip-cidr",
			"203.0.113.0/24",
			"--expires-at",
			&FAR_FUTURE.to_string(),
			"--save-sent",
			"off",
		],
	);
	assert_eq!(code, 0);
	created["secret"].as_str().expect("secret").to_string()
}

/// Whether `secret` opens the credential `label` of bob from a client in
/// the allowed range.
fn admits(env: &Env, label: &str, secret: &str) -> bool {
	let store = AppPasswordStore::open(&env.data_dir()).expect("open store");
	store
		.for_account("bob")
		.iter()
		.find(|app| app.label == label)
		.is_some_and(|app| {
			app.admits(
				secret,
				&Policy::ASCII_ONLY,
				Some("203.0.113.5".parse().expect("ip")),
				NOW,
			)
		})
}

fn listed(env: &Env) -> Value {
	run(env, &["list"]).1
}

#[test]
fn rotate_replaces_the_secret_and_keeps_everything_else() {
	let env = env("");
	let old = phone(&env);
	let before = listed(&env);
	assert!(admits(&env, "phone", &old));

	let (code, mut rotated) = run(&env, &["rotate", "bob", "phone", "--yes"]);
	assert_eq!(code, 0);
	let new = rotated["secret"].take();
	let new = new
		.as_str()
		.expect("the new secret is printed once")
		.to_string();
	assert_ne!(new, old);
	assert_eq!(new.len(), old.len());
	assert_eq!(
		rotated,
		json!({
			"result": "saved", "action": "rotate", "account": "bob", "label": "phone",
			"secret": null, "reload": "no-server",
		})
	);
	assert!(!admits(&env, "phone", &old), "the old secret still works");
	assert!(admits(&env, "phone", &new), "the new secret does not work");
	assert_eq!(listed(&env), before, "expiry, range and save-sent changed");
}

#[test]
fn rotate_without_yes_off_a_terminal_changes_nothing() {
	let env = env("");
	let old = phone(&env);
	let (code, stdout, stderr) = plain(&env, &["rotate", "bob", "phone", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(stderr.contains("--yes"), "{stderr}");
	assert!(admits(&env, "phone", &old));
}

#[test]
fn a_dry_run_rotation_prints_no_secret_and_changes_nothing() {
	let env = env("");
	let old = phone(&env);
	let (code, plan) = run(&env, &["rotate", "bob", "phone", "--dry-run"]);
	assert_eq!(code, 0);
	assert_eq!(
		plan,
		json!({"result": "dry-run", "action": "rotate", "account": "bob", "label": "phone"})
	);
	assert!(admits(&env, "phone", &old));
}

#[test]
fn rotate_and_rename_refuse_a_credential_that_is_not_there() {
	let env = env("");
	phone(&env);
	for (args, shown) in [
		(vec!["rotate", "bob", "tablet", "--yes"], "bob/tablet"),
		(vec!["rotate", "nobody", "phone", "--yes"], "nobody/phone"),
		(vec!["rename", "bob", "tablet", "laptop"], "bob/tablet"),
	] {
		let mut full = args.clone();
		full.push("--json");
		let (code, stdout, stderr) = plain(&env, &full);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{args:?}");
		assert!(stderr.contains(shown), "{args:?}: {stderr}");
	}
}

#[test]
fn rename_changes_the_label_and_nothing_else() {
	let env = env("");
	let secret = phone(&env);
	let mut before = listed(&env);
	let (code, renamed) = run(&env, &["rename", "bob", "phone", "work phone"]);
	assert_eq!(code, 0);
	assert_eq!(
		renamed,
		json!({
			"result": "saved", "action": "rename", "account": "bob",
			"label": "work phone", "previous_label": "phone",
		})
	);
	before[0]["label"] = "work phone".into();
	assert_eq!(listed(&env), before);
	assert!(
		admits(&env, "work phone", &secret),
		"the secret stopped working"
	);
	assert!(!admits(&env, "phone", &secret));
}

#[test]
fn rename_to_the_same_label_is_unchanged() {
	let env = env("");
	phone(&env);
	let (code, same) = run(&env, &["rename", "bob", "phone", "phone"]);
	assert_eq!((code, same["result"].as_str()), (0, Some("unchanged")));
}

#[test]
fn rename_refuses_a_label_that_is_taken() {
	let env = env("");
	phone(&env);
	assert_eq!(run(&env, &["create", "bob", "tablet"]).0, 0);
	let (code, stdout, stderr) = plain(&env, &["rename", "bob", "phone", "tablet", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""), "{stderr}");
	assert!(stderr.contains("tablet"), "{stderr}");
	let labels: Vec<String> = listed(&env)
		.as_array()
		.expect("array")
		.iter()
		.map(|row| row["label"].as_str().expect("label").to_string())
		.collect();
	assert_eq!(labels, ["phone", "tablet"]);
}

#[test]
fn labels_are_bounded_and_printable() {
	let env = env("");
	phone(&env);
	let too_long = "x".repeat(65);
	for (label, needle) in [
		("", "must not be empty"),
		("tab\there", "control characters"),
		("esc\u{1b}[2J", "control characters"),
		(too_long.as_str(), "at most 64 characters"),
	] {
		let (code, stdout, stderr) = plain(&env, &["rename", "bob", "phone", label, "--json"]);
		assert_eq!(
			(code, stdout.as_str()),
			(Some(2), ""),
			"{label:?}: {stderr}"
		);
		assert!(stderr.contains(needle), "{label:?}: {stderr}");
		let (code, stdout, stderr) = plain(&env, &["create", "bob", label, "--json"]);
		assert_eq!(
			(code, stdout.as_str()),
			(Some(2), ""),
			"create {label:?}: {stderr}"
		);
		assert!(stderr.contains(needle), "create {label:?}: {stderr}");
	}
	assert_eq!(listed(&env).as_array().expect("array").len(), 1);
}

#[test]
fn list_escapes_a_label_the_store_holds() {
	let env = env("");
	add_account(&env, "bob");
	std::fs::write(
		env.data_dir().join("app_passwords.toml"),
		"[[accounts.bob.passwords]]\nlabel = \"old\\u001b[2Jlabel\"\nhash = \"x\"\n",
	)
	.expect("plant");
	let (code, stdout, _) = plain(&env, &["list"]);
	assert_eq!(code, Some(0));
	assert!(
		!stdout.contains('\u{1b}'),
		"an escape reached the terminal: {stdout:?}"
	);
	assert!(stdout.contains("old\\u{1b}[2Jlabel"), "{stdout:?}");
}
