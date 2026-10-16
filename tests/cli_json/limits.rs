//! `epistle limits set|unset --json`, with and without `--dry-run`: stdout
//! is one JSON object whatever the change turns out to be.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

fn limits(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["limits", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

#[test]
fn a_dry_run_set_prints_the_diff_inside_the_object() {
	let env = env("");
	let (code, mut plan) = limits(&env, &["set", "quota", "2G", "--dry-run"]);
	assert_eq!(code, 0);
	let diff = plan["diff"].take();
	let diff = diff.as_str().expect("diff is a string");
	assert!(
		diff.contains("+quota") && diff.contains("--- "),
		"the diff of the change is missing: {diff}"
	);
	assert_eq!(
		plan,
		json!({
			"result": "dry-run", "action": "set", "key": "quota",
			"scope": {"type": "global"}, "diff": null,
		})
	);
	let configuration = std::fs::read_to_string(&env.config).expect("read config");
	assert!(
		!configuration.contains("quota"),
		"a dry run wrote the limit"
	);
}

#[test]
fn a_dry_run_unset_with_nothing_to_remove_is_still_json() {
	let env = env("");
	assert_eq!(
		limits(&env, &["unset", "quota", "--dry-run"]),
		(
			0,
			json!({
				"result": "dry-run", "action": "unset", "key": "quota",
				"scope": {"type": "global"}, "diff": "",
			})
		)
	);
}

#[test]
fn set_then_unset_report_what_changed() {
	let env = env("");
	assert_eq!(
		limits(&env, &["set", "quota", "2G"]),
		(
			0,
			json!({
				"result": "saved", "action": "set", "key": "quota",
				"scope": {"type": "global"}, "value": 2_147_483_648_u64,
			})
		)
	);
	assert_eq!(
		limits(&env, &["unset", "quota"]),
		(
			0,
			json!({
				"result": "saved", "action": "unset", "key": "quota",
				"scope": {"type": "global"}, "value": null,
			})
		)
	);
	assert_eq!(limits(&env, &["unset", "quota"]).1["result"], "unchanged");
}
