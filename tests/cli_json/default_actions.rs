//! A resource with a default action (`suppression` and `delivery` list
//! when none is named) takes `--json` in that form too.

use serde_json::{Value, json};

use crate::harness::{env, epistle, json};

fn run(args: &[&str]) -> (i32, Value) {
	json(&epistle(args, b""))
}

#[test]
fn suppression_without_an_action_lists_as_json() {
	let env = env("");
	assert_eq!(
		run(&["suppression", "--config", &env.config, "--json"]),
		(0, json!([]))
	);
	let added = run(&[
		"suppression",
		"add",
		"gone@example.net",
		"--config",
		&env.config,
		"--json",
	]);
	assert_eq!(added.0, 0);
	let (code, listed) = run(&["suppression", "--config", &env.config, "--json"]);
	assert_eq!(code, 0);
	assert_eq!(listed[0]["address"], "gone@example.net");
	assert_eq!(listed.as_array().map(Vec::len), Some(1));
	// The flag before the action reaches the action.
	assert_eq!(
		run(&["suppression", "--json", "list", "--config", &env.config]),
		(code, listed)
	);
}

#[test]
fn delivery_without_an_action_lists_as_json() {
	let env = env("[storage]\ndelivery_log_days = 7\n");
	assert_eq!(
		run(&["delivery", "--config", &env.config, "--json"]),
		(0, json!([]))
	);
	assert_eq!(
		run(&["delivery", "--json", "list", "--config", &env.config]),
		(0, json!([]))
	);
}

#[test]
fn the_older_remove_form_prints_its_result_as_json() {
	let env = env("");
	run(&[
		"suppression",
		"add",
		"gone@example.net",
		"--config",
		&env.config,
		"--json",
	]);
	assert_eq!(
		run(&[
			"suppression",
			"--remove",
			"gone@example.net",
			"--config",
			&env.config,
			"--json",
		]),
		(
			0,
			json!({"result": "saved", "action": "remove", "address": "gone@example.net", "account": null})
		)
	);
}
