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

#[test]
fn up_down_stop_and_start_print_one_object_each() {
	let env = env("");
	let bin = chatty_podup(&env);
	let cases: [(&[&str], serde_json::Value); 6] = [
		(
			&["up"],
			json!({"result": "done", "action": "up", "service": null}),
		),
		(
			&["down"],
			json!({"result": "done", "action": "down", "service": null}),
		),
		(
			&["stop"],
			json!({"result": "done", "action": "stop", "service": null}),
		),
		(
			&["stop", "mail"],
			json!({"result": "done", "action": "stop", "service": "mail"}),
		),
		(
			&["start"],
			json!({"result": "done", "action": "start", "service": null}),
		),
		(
			&["start", "mail"],
			json!({"result": "done", "action": "start", "service": "mail"}),
		),
	];
	for (args, expected) in cases {
		let mut full = vec!["stack", "--config", &env.config];
		full.extend_from_slice(args);
		full.push("--json");
		let output = epistle_in(&full, b"", Some(&bin));
		assert_eq!(json(&output), (0, expected), "{args:?}");
		assert!(
			String::from_utf8_lossy(&output.stderr).contains("podup says:"),
			"{args:?}: podup's output should have gone to stderr"
		);
	}
}

/// A compose file with the four services and their limits, as JSON.
fn limits_compose(env: &crate::harness::Env) {
	let compose = env.data_dir().join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("compose dir");
	std::fs::write(
		&compose,
		r#"{"services":{
			"mail":{"mem_limit":"1g","pids_limit":1024},
			"db":{"mem_limit":"1g","pids_limit":256},
			"clamav":{"mem_limit":"3g","pids_limit":128},
			"freshclam":{"mem_limit":"2g","pids_limit":32}}}"#,
	)
	.expect("write compose");
}

/// `stdout` must be exactly one JSON document, however many lines it takes.
fn single_document(output: &std::process::Output) -> serde_json::Value {
	let mut documents = serde_json::Deserializer::from_slice(&output.stdout)
		.into_iter::<serde_json::Value>()
		.collect::<Result<Vec<_>, _>>()
		.unwrap_or_else(|error| panic!("stdout is not JSON: {error}"));
	assert_eq!(
		documents.len(),
		1,
		"stdout holds {} documents: {}",
		documents.len(),
		String::from_utf8_lossy(&output.stdout)
	);
	documents.remove(0)
}

#[test]
fn resources_prints_one_document() {
	let env = env("");
	limits_compose(&env);
	let output = epistle_in(
		&["stack", "--config", &env.config, "resources", "--json"],
		b"",
		None,
	);
	assert_eq!(output.status.code(), Some(0));
	let listed = single_document(&output);
	assert_eq!(listed["total_bytes"], 7 * 1024 * 1024 * 1024_u64);
	assert_eq!(listed["services"][0]["service"], "clamav");
}

#[test]
fn resources_set_prints_one_document() {
	let env = env("");
	limits_compose(&env);
	let output = epistle_in(
		&[
			"stack",
			"--config",
			&env.config,
			"resources",
			"set",
			"clamav",
			"--memory",
			"2g",
			"--json",
		],
		b"",
		None,
	);
	assert_eq!(output.status.code(), Some(0));
	let changed = single_document(&output);
	assert_eq!(changed["before"]["memory"], "3g");
	assert_eq!(changed["after"]["memory"], "2g");
}
