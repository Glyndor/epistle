//! `epistle account ... --json`: one result object per change.

use serde_json::json;

use crate::harness::{PASSWORD, add_account, env, epistle, json};

fn account(config: &str, args: &[&str]) -> (i32, serde_json::Value) {
	let mut full = vec!["account", "--config", config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, PASSWORD))
}

#[test]
fn add_prints_the_new_account() {
	let env = env("");
	let (code, value) = account(
		&env.config,
		&[
			"add",
			"carol",
			"--address",
			"carol@example.org",
			"--display-name",
			"Carol",
		],
	);
	assert_eq!(code, 0);
	assert_eq!(
		value,
		json!({
			"result": "saved", "action": "add", "account": "carol",
			"addresses": ["carol@example.org"], "display_name": "Carol", "reload": "no-server",
		})
	);
	assert!(
		!value.to_string().contains("Zq8!"),
		"the password reached stdout"
	);
}

#[test]
fn disable_then_disable_again_reports_unchanged() {
	let env = env("");
	add_account(&env, "bob");
	let expected = |result: &str| {
		json!({
			"result": result, "action": "disable", "account": "bob",
			"disabled": true, "reload": "no-server",
		})
	};
	assert_eq!(
		account(&env.config, &["disable", "bob"]),
		(0, expected("saved"))
	);
	assert_eq!(
		account(&env.config, &["disable", "bob"]),
		(0, expected("unchanged"))
	);
	assert_eq!(
		account(&env.config, &["enable", "bob"]),
		(
			0,
			json!({
				"result": "saved", "action": "enable", "account": "bob",
				"disabled": false, "reload": "no-server",
			})
		)
	);
}

#[test]
fn settings_changes_name_the_value_they_set() {
	let env = env("srs_secret = \"0123456789abcdef0123456789abcdef\"\n");
	add_account(&env, "bob");
	let cases: Vec<(Vec<&str>, serde_json::Value)> = vec![
		(
			vec!["password", "bob"],
			json!({"result": "saved", "action": "password", "account": "bob", "reload": "no-server"}),
		),
		(
			vec!["set-name", "bob", "Bob B"],
			json!({"result": "saved", "action": "set-name", "account": "bob", "display_name": "Bob B"}),
		),
		(
			vec!["quota", "bob", "2K"],
			json!({"result": "saved", "action": "quota", "account": "bob", "quota_bytes": 2048}),
		),
		(
			vec!["protocols", "bob", "imap,smtp"],
			json!({"result": "saved", "action": "protocols", "account": "bob", "protocols": ["imap", "smtp"]}),
		),
		(
			vec!["save-sent", "bob", "off"],
			json!({"result": "saved", "action": "save-sent", "account": "bob", "save_sent": false}),
		),
		(
			vec!["address", "add", "bob", "b2@example.org"],
			json!({"result": "saved", "action": "address add", "account": "bob", "address": "b2@example.org"}),
		),
		(
			vec!["address", "remove", "bob", "b2@example.org"],
			json!({"result": "saved", "action": "address remove", "account": "bob", "address": "b2@example.org"}),
		),
		(
			vec!["forward", "add", "bob", "out@example.com"],
			json!({"result": "saved", "action": "forward add", "account": "bob", "address": "out@example.com"}),
		),
		(
			vec!["forward", "remove", "bob", "out@example.com"],
			json!({"result": "saved", "action": "forward remove", "account": "bob", "address": "out@example.com"}),
		),
		(
			vec!["catch-all", "add", "bob", "example.org"],
			json!({"result": "saved", "action": "catch-all add", "account": "bob", "domain": "example.org"}),
		),
		(
			vec!["catch-all", "remove", "bob", "example.org"],
			json!({"result": "saved", "action": "catch-all remove", "account": "bob", "domain": "example.org"}),
		),
		(
			vec!["2fa", "disable", "bob", "--yes"],
			json!({"result": "saved", "action": "2fa disable", "account": "bob", "enrolled": false}),
		),
	];
	for (args, expected) in cases {
		assert_eq!(account(&env.config, &args), (0, expected), "{args:?}");
	}
}

#[test]
fn remove_reports_what_went() {
	let env = env("");
	add_account(&env, "bob");
	assert_eq!(
		account(&env.config, &["remove", "bob", "--queue", "drain", "--yes"]),
		(
			0,
			json!({
				"result": "saved", "action": "remove", "account": "bob",
				"removed": {
					"mailbox_files": 0, "masked_addresses": 0, "app_passwords": 0,
					"suppressed_addresses": 0, "queued_messages_discarded": 0,
					"queued_messages_left": 0, "bayes_tokens_removed": 0,
				},
				"reload": "no-server",
			})
		)
	);
}

#[test]
fn find_log_id_lists_the_matching_accounts() {
	let env = env("");
	add_account(&env, "bob");
	let shown = epistle(
		&["account", "--config", &env.config, "show", "bob", "--json"],
		b"",
	);
	let (_, view) = json(&shown);
	let log_id = view["log_id"].as_str().expect("log id").to_string();
	assert_eq!(
		account(&env.config, &["find-log-id", &log_id]),
		(0, json!({"log_id": log_id, "accounts": ["bob"]}))
	);
}

#[test]
fn a_refusal_prints_nothing_on_stdout() {
	let env =
		env("[[accounts]]\nname = \"postmaster\"\naddresses = [\"postmaster@example.org\"]\n");
	let output = epistle(
		&[
			"account",
			"--config",
			&env.config,
			"disable",
			"nobody",
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
