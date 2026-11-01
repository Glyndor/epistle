//! `--json` on `alias` and `domain`.

use serde_json::{Value, json};

use crate::harness::{add_account, env, epistle, json};

fn run(config: &str, resource: &str, args: &[&str]) -> (i32, Value) {
	let mut full = vec![resource, "--config", config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

fn restart_needed(action: &str, key: &str, value: &str) -> Value {
	json!({ "result": "saved", "action": action, key: value, "reload": "restart-needed" })
}

#[test]
fn alias_lifecycle() {
	let env = env("");
	add_account(&env, "alice");
	add_account(&env, "bob");
	let team = "team@example.org";
	let cases = [
		(
			vec!["add", team, "alice@example.org"],
			restart_needed("add", "alias", team),
		),
		(
			vec!["member", "add", team, "bob@example.org"],
			restart_needed("member add", "alias", team),
		),
		(
			vec!["member", "remove", team, "bob@example.org"],
			restart_needed("member remove", "alias", team),
		),
		(
			vec!["sender", "add", team, "bob@example.org"],
			restart_needed("sender add", "alias", team),
		),
		(
			vec!["sender", "remove", team, "bob@example.org"],
			restart_needed("sender remove", "alias", team),
		),
		(
			vec!["disable", team],
			json!({"result": "saved", "action": "disable", "alias": team, "enabled": false}),
		),
		(
			vec!["disable", team],
			json!({"result": "unchanged", "action": "disable", "alias": team, "enabled": false}),
		),
		(
			vec!["enable", team],
			json!({"result": "saved", "action": "enable", "alias": team, "enabled": true}),
		),
		(
			vec!["remove", team, "--yes"],
			restart_needed("remove", "alias", team),
		),
	];
	for (args, expected) in cases {
		assert_eq!(run(&env.config, "alias", &args), (0, expected), "{args:?}");
	}
}

#[test]
fn domain_add_lists_the_records_to_publish() {
	let env = env("");
	let (code, mut value) = run(&env.config, "domain", &["add", "example.net"]);
	assert_eq!(code, 0);
	let records = value["records"].take();
	assert_eq!(
		value,
		json!({
			"result": "saved", "action": "add", "domain": "example.net",
			"records": null, "reload": "restart-needed",
		})
	);
	let records: Vec<&str> = records
		.as_array()
		.expect("records array")
		.iter()
		.map(|record| record.as_str().expect("record line"))
		.collect();
	assert!(
		records.contains(&"example.net 3600 IN MX 10 mail.example.org"),
		"no MX line in {records:?}"
	);
	assert!(
		records
			.iter()
			.all(|line| line.starts_with('_') || line.contains("example.net ")),
		"a record for another name: {records:?}"
	);
}

#[test]
fn domain_alias_and_remove() {
	let env = env("");
	assert_eq!(
		run(
			&env.config,
			"domain",
			&["alias", "add", "example.com", "example.org"]
		),
		(0, restart_needed("alias add", "alias", "example.com"))
	);
	assert_eq!(
		run(
			&env.config,
			"domain",
			&["alias", "remove", "example.com", "--yes"]
		),
		(0, restart_needed("alias remove", "alias", "example.com"))
	);
	assert_eq!(run(&env.config, "domain", &["add", "example.net"]).0, 0);
	assert_eq!(
		run(&env.config, "domain", &["remove", "example.net", "--yes"]),
		(0, restart_needed("remove", "domain", "example.net"))
	);
}
