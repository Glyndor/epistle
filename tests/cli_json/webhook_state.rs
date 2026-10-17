//! `webhook enable` and `webhook disable`, and `enabled` in `webhook show`.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

const SECTION: &str = "# keep me
[webhook]
url = \"https://hooks.example.net/in\"
secret = \"s3cr3t-value-for-the-webhook\"
";

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["webhook", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

fn text(env: &Env) -> String {
	std::fs::read_to_string(&env.config).expect("read config")
}

#[test]
fn show_says_whether_the_webhook_is_on() {
	let env = env(SECTION);
	assert_eq!(
		run(&env, &["show"]),
		(
			0,
			json!({"url": "https://hooks.example.net/in", "secret": "set", "enabled": true})
		)
	);
	let output = epistle(&["webhook", "--config", &env.config, "show"], b"");
	let stdout = String::from_utf8_lossy(&output.stdout);
	assert_eq!(
		stdout,
		"url\thttps://hooks.example.net/in\nsecret\tset\nenabled\tyes\n"
	);
	assert!(!stdout.contains("s3cr3t"), "the secret reached stdout");
}

#[test]
fn disable_then_enable_the_webhook() {
	let env = env(SECTION);
	let disabled = json!({
		"result": "saved", "action": "disable", "enabled": false, "reload": "restart-needed",
	});
	assert_eq!(run(&env, &["disable"]), (0, disabled));
	assert!(text(&env).contains("enabled = false"), "{}", text(&env));
	assert!(text(&env).contains("# keep me"));
	assert!(text(&env).contains("url = \"https://hooks.example.net/in\""));
	assert_eq!(run(&env, &["disable"]).1["result"], "unchanged");
	assert_eq!(run(&env, &["show"]).1["enabled"], false);

	let enabled = json!({
		"result": "saved", "action": "enable", "enabled": true, "reload": "restart-needed",
	});
	assert_eq!(run(&env, &["enable"]), (0, enabled));
	assert!(!text(&env).contains("enabled"), "{}", text(&env));
	assert_eq!(run(&env, &["enable"]).1["result"], "unchanged");
}

#[test]
fn setting_the_url_keeps_a_disabled_webhook_disabled() {
	let env = env(SECTION);
	assert_eq!(run(&env, &["disable"]).0, 0);
	assert_eq!(run(&env, &["set", "https://hooks.example.net/other"]).0, 0);
	assert_eq!(run(&env, &["show"]).1["enabled"], false);
}

#[test]
fn a_dry_run_changes_nothing() {
	let env = env(SECTION);
	let before = text(&env);
	let (code, value) = run(&env, &["disable", "--dry-run"]);
	assert_eq!((code, value["result"].as_str()), (0, Some("dry-run")));
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("+enabled = false")),
		"diff: {}",
		value["diff"]
	);
	assert!(
		!value.to_string().contains("s3cr3t"),
		"the secret reached the diff"
	);
	assert_eq!(text(&env), before);
}

#[test]
fn without_a_webhook_there_is_nothing_to_switch() {
	let env = env("");
	for action in ["enable", "disable"] {
		let output = epistle(&["webhook", "--config", &env.config, action, "--json"], b"");
		assert_eq!(output.status.code(), Some(2), "{action}");
		assert!(output.stdout.is_empty(), "{action}");
		assert_eq!(
			String::from_utf8_lossy(&output.stderr).trim_end(),
			"error: no webhook is configured; run `epistle webhook set` first",
			"{action}"
		);
	}
	assert!(
		!text(&env).contains("[webhook]"),
		"an empty section was created"
	);
}
