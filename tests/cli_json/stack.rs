//! `--json` while podup runs: podup's own stdout goes to stderr, so
//! epistle's stdout stays one JSON object.

use serde_json::json;

use crate::harness::{chatty_podup, env, epistle_in, json};

#[test]
fn stack_restart_prints_only_the_object() {
	let env = env("");
	let bin = chatty_podup(&env);
	let output = epistle_in(
		&[
			"stack",
			"--config",
			&env.config,
			"restart",
			"mail",
			"--json",
		],
		b"",
		Some(&bin),
	);
	assert_eq!(
		json(&output),
		(
			0,
			json!({"result": "done", "action": "restart", "service": "mail"})
		)
	);
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("podup says: -f"),
		"podup's output should have gone to stderr"
	);
}

#[test]
fn a_config_edit_that_restarts_mail_keeps_stdout_clean() {
	let env = env("");
	let bin = chatty_podup(&env);
	let output = epistle_in(
		&[
			"relay",
			"--config",
			&env.config,
			"add",
			"--domain",
			"example.net",
			"--host",
			"relay.example.net",
			"--json",
		],
		b"",
		Some(&bin),
	);
	assert_eq!(
		json(&output),
		(
			0,
			json!({
				"result": "saved", "action": "add", "account": null, "domain": "example.net",
				"host": "relay.example.net", "reload": "restarted",
			})
		)
	);
}

#[test]
fn stack_logs_refuses_json() {
	let env = env("");
	let bin = chatty_podup(&env);
	let output = epistle_in(
		&["stack", "--config", &env.config, "logs", "--json"],
		b"",
		Some(&bin),
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	assert_eq!(
		String::from_utf8_lossy(&output.stderr),
		"error: stack logs streams the services' raw log lines; it has no --json form\n"
	);
}
