//! `domain set`: the per-domain storage quota and submission rate, written
//! to the same `domain_quotas` and `domain_submission_limits` maps that
//! `limits set --domain` edits.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["domain", "--config", &env.config, "set"];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

fn refused(env: &Env, args: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["domain", "--config", &env.config, "set"];
	full.extend_from_slice(args);
	full.push("--json");
	let output = epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

fn overrides(env: &Env) -> Value {
	let output = epistle(&["limits", "--config", &env.config, "show", "--json"], b"");
	let (_, value) = json(&output);
	value["domain-overrides"]["example.org"].clone()
}

#[test]
fn set_then_clear_the_quota_and_the_submission_rate() {
	let env = env("# kept\n");
	assert_eq!(
		run(
			&env,
			&["example.org", "--quota", "2G", "--submission-rate", "50"]
		),
		(
			0,
			json!({
				"result": "saved", "action": "set", "domain": "example.org",
				"quota": 2_147_483_648_u64, "submission_rate": 50, "reload": "restart-needed",
			})
		)
	);
	assert_eq!(
		overrides(&env),
		json!({"quota": 2_147_483_648_u64, "submission-rate": 50})
	);
	assert!(
		std::fs::read_to_string(&env.config)
			.expect("read")
			.contains("# kept")
	);

	assert_eq!(
		run(&env, &["example.org", "--no-quota"]),
		(
			0,
			json!({
				"result": "saved", "action": "set", "domain": "example.org",
				"quota": null, "reload": "restart-needed",
			})
		)
	);
	assert_eq!(
		overrides(&env),
		json!({"quota": null, "submission-rate": 50})
	);
	assert_eq!(
		run(&env, &["example.org", "--no-quota"]).1["result"],
		"unchanged"
	);
}

#[test]
fn show_lists_the_overrides_of_one_domain() {
	let env = env("");
	run(
		&env,
		&["example.org", "--quota", "1G", "--submission-rate", "7"],
	);
	let output = epistle(
		&[
			"domain",
			"--config",
			&env.config,
			"show",
			"example.org",
			"--json",
		],
		b"",
	);
	let (_, shown) = json(&output);
	assert_eq!(shown["quota"], 1_073_741_824_u64);
	assert_eq!(shown["submission_rate"], 7);
}

#[test]
fn a_dry_run_prints_the_diff_and_writes_nothing() {
	let env = env("");
	let before = std::fs::read_to_string(&env.config).expect("read");
	let mut full = vec!["domain", "--config", &env.config, "set", "example.org"];
	full.extend_from_slice(&["--quota", "5M", "--dry-run", "--json"]);
	let (code, value) = json(&epistle(&full, b""));
	assert_eq!((code, value["result"].as_str()), (0, Some("dry-run")));
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("domain_quotas")),
		"diff: {}",
		value["diff"]
	);
	assert_eq!(std::fs::read_to_string(&env.config).expect("read"), before);
}

#[test]
fn a_domain_that_is_not_configured_is_refused() {
	let env = env("");
	let (code, stdout, stderr) = refused(&env, &["nowhere.example", "--quota", "1G"]);
	assert_eq!(code, Some(2));
	assert_eq!(stdout, "");
	assert_eq!(
		stderr.trim_end(),
		"error: domain nowhere.example is not configured"
	);
}

#[test]
fn nothing_to_set_is_a_usage_error() {
	let env = env("");
	let (code, stdout, stderr) = refused(&env, &["example.org"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(stderr.contains("--quota"), "stderr: {stderr}");
}

#[test]
fn bad_values_are_refused_before_anything_is_written() {
	let env = env("");
	let before = std::fs::read_to_string(&env.config).expect("read");
	for (args, needle) in [
		(vec!["example.org", "--quota", "lots"], "quota"),
		(
			vec!["example.org", "--submission-rate", "0"],
			"--no-submission-rate",
		),
		(
			vec!["example.org", "--submission-rate", "-5"],
			"submission-rate",
		),
		(
			vec!["example.org", "--quota", "1G", "--no-quota"],
			"cannot be used with",
		),
	] {
		let (code, stdout, stderr) = refused(&env, &args);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{args:?}: {stderr}");
		assert!(stderr.contains(needle), "{args:?}: {stderr}");
	}
	assert_eq!(std::fs::read_to_string(&env.config).expect("read"), before);
}

#[test]
fn removing_a_domain_drops_its_overrides() {
	let env = env("");
	assert_eq!(run_domain(&env, &["add", "example.net"]).0, 0);
	run(
		&env,
		&["example.net", "--quota", "1G", "--submission-rate", "9"],
	);
	let (code, value) = run_domain(&env, &["remove", "example.net", "--yes"]);
	assert_eq!(
		(code, value["result"].as_str()),
		(0, Some("saved")),
		"{value}"
	);
	let text = std::fs::read_to_string(&env.config).expect("read");
	assert!(!text.contains("example.net"), "left behind:\n{text}");
}

fn run_domain(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["domain", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}
