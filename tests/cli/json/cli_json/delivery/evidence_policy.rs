//! `epistle evidence policy set` against the real binary: how long evidence
//! is kept is the operator's to say, within bounds, and a value outside them
//! leaves the policy file as it was.

use serde_json::Value;

use crate::harness::{Env, env, epistle};

/// A data directory whose evidence chain exists, as it does once the server
/// has run: `evidence policy set` needs it to find the operator.
fn prepared() -> Env {
	let env = env("");
	epistle::evidence::chain::Chain::open(&env.data_dir().join("evidence")).expect("chain");
	env
}

fn evidence(env: &Env, args: &[&str]) -> std::process::Output {
	let mut full = vec!["evidence", "policy"];
	full.extend_from_slice(args);
	full.extend_from_slice(&["--config", &env.config]);
	epistle(&full, b"")
}

fn set(env: &Env, class: &str, mode: &str, days: &str) -> std::process::Output {
	evidence(
		env,
		&[
			"set", "--class", class, "--mode", mode, "--days", days, "--json",
		],
	)
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The rules `evidence policy show --json` prints.
fn rules(env: &Env) -> Vec<Value> {
	let output = evidence(env, &["show", "--json"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let shown: Value = serde_json::from_slice(&output.stdout).expect("JSON");
	shown["rules"].as_array().expect("rules").clone()
}

#[test]
fn days_outside_one_to_the_longest_are_refused_and_change_nothing() {
	let env = prepared();
	for days in ["0", "9151", "4294967295"] {
		let output = set(&env, "marketing", "full", days);
		assert_eq!(output.status.code(), Some(2), "{days}");
		assert!(output.stdout.is_empty(), "{days}");
		assert!(
			stderr(&output).contains("days must be between 1 and 9150"),
			"{days}: {}",
			stderr(&output)
		);
		assert!(rules(&env).is_empty(), "{days}");
	}
	for days in ["abc", "-1", "1.5", "4294967296"] {
		let output = set(&env, "marketing", "full", days);
		assert_eq!(output.status.code(), Some(2), "{days}");
		assert!(output.stdout.is_empty(), "{days}");
		assert!(rules(&env).is_empty(), "{days}");
	}
}

#[test]
fn the_edges_of_the_range_are_kept() {
	let env = prepared();
	for (class, days) in [("marketing", "1"), ("personal", "9150")] {
		let output = set(&env, class, "metadata", days);
		assert_eq!(output.status.code(), Some(0), "{days}: {}", stderr(&output));
	}
	let kept = rules(&env);
	assert_eq!(kept.len(), 2);
	let days = |class: &str| {
		kept.iter()
			.find(|rule| rule["class"] == class)
			.expect("rule")["days"]
			.clone()
	};
	assert_eq!(days("marketing"), Value::from(1));
	assert_eq!(days("personal"), Value::from(9150));
}

#[test]
fn turning_a_class_off_ignores_the_days_it_was_given() {
	let env = prepared();
	let output = set(&env, "marketing", "off", "0");
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let kept = rules(&env);
	assert_eq!(kept.len(), 1);
	assert_eq!(kept[0]["mode"], "off");
	assert_eq!(kept[0]["days"], 0);
	// Even a value no mode accepts is not looked at once the class is off.
	let output = set(&env, "personal", "off", "99999");
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let personal = rules(&env)
		.into_iter()
		.find(|rule| rule["class"] == "personal")
		.expect("the personal rule");
	assert_eq!(personal["mode"], "off");
	assert_eq!(personal["days"], 0);
}

#[test]
fn transactional_mail_cannot_be_switched_off_and_a_class_must_be_one() {
	let env = prepared();
	let off = set(&env, "transactional", "off", "30");
	assert_eq!(off.status.code(), Some(2));
	assert!(
		stderr(&off).contains("transactional mail always keeps evidence"),
		"{}",
		stderr(&off)
	);
	let unknown = set(&env, "bulk", "full", "30");
	assert_eq!(unknown.status.code(), Some(2));
	assert!(
		stderr(&unknown).contains("unknown class"),
		"{}",
		stderr(&unknown)
	);
	let loud = set(&env, "marketing", "loud", "30");
	assert_eq!(loud.status.code(), Some(2));
	assert!(rules(&env).is_empty());
}

#[test]
fn an_account_and_a_tenant_cannot_both_be_named() {
	let env = prepared();
	let output = evidence(
		&env,
		&[
			"set",
			"--class",
			"all",
			"--mode",
			"metadata",
			"--account",
			"alice",
			"--tenant",
			"acme",
		],
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(
		stderr(&output).contains("cannot be used with"),
		"{}",
		stderr(&output)
	);
	assert!(rules(&env).is_empty());
}
