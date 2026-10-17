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
	assert!(!stdout.contains("s3cr3t"), "the secret reached stdout");
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
	assert!(
		!value.to_string().contains("s3cr3t"),
		"the secret reached the diff"
	);
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
	assert!(text(&env) == before, "a dry run wrote the file");
}

#[test]
fn without_a_webhook_there_is_nothing_to_switch() {
	let env = env("");
	for action in ["enable", "disable"] {
		let output = epistle(&["webhook", "--config", &env.config, action, "--json"], b"");
		assert_eq!(output.status.code(), Some(3), "{action}");
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

const WITH_ALERT: &str = "[webhook]
url = \"https://hooks.example.net/in\"
secret = \"s3cr3t-value-for-the-webhook\"

[[alerts]]
name = \"spool\"
metric = \"accepted\"
op = \">\"
threshold = 100
window_secs = 300
webhook = true
cooldown_secs = 3600
";

fn disable(env: &Env, extra: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["webhook", "--config", &env.config, "disable"];
	full.extend_from_slice(extra);
	let output = epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

#[test]
fn disabling_a_webhook_an_alert_posts_to_is_refused_without_yes() {
	let env = env(WITH_ALERT);
	let before = text(&env);
	for extra in [vec![], vec!["--json"]] {
		let (code, stdout, stderr) = disable(&env, &extra);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{extra:?}");
		assert!(stderr.contains("alert \"spool\" posts to it"), "{stderr}");
		assert!(stderr.contains("--yes"), "{stderr}");
	}
	assert!(text(&env) == before, "a refused disable wrote the file");
}

#[test]
fn disabling_says_which_alarms_stop() {
	let env = env(WITH_ALERT);
	let (code, stdout, stderr) = disable(&env, &["--yes", "--json"]);
	assert_eq!(code, Some(0), "{stderr}");
	assert_eq!(stdout.lines().count(), 1);
	assert!(stderr.contains("alert \"spool\""), "{stderr}");
	for event in ["outbound_virus", "dkim_rotation_failed", "delivery_failed"] {
		assert!(stderr.contains(event), "{event} missing from: {stderr}");
	}
	assert!(text(&env).contains("enabled = false"));
}

#[test]
fn disabling_with_no_alert_still_says_what_stops_but_needs_no_yes() {
	let env = env(SECTION);
	let (code, _, stderr) = disable(&env, &["--json"]);
	assert_eq!(code, Some(0), "{stderr}");
	assert!(stderr.contains("outbound_virus"), "{stderr}");
	assert!(!stderr.contains("alert \""), "{stderr}");
}

#[test]
fn a_dry_run_asks_for_nothing() {
	let env = env(WITH_ALERT);
	let (code, _, _) = disable(&env, &["--dry-run", "--json"]);
	assert_eq!(code, Some(0));
}

#[test]
fn config_check_warns_about_an_alert_that_cannot_post() {
	let env = env(WITH_ALERT);
	let check = |env: &Env| {
		let output = epistle(&["config-check", "--config", &env.config, "--json"], b"");
		assert_eq!(output.status.code(), Some(0));
		let (_, value) = json(&output);
		value["warnings"]
			.as_array()
			.expect("warnings")
			.iter()
			.map(|w| w.as_str().expect("text").to_string())
			.collect::<Vec<_>>()
	};
	assert!(
		!check(&env).iter().any(|w| w.contains("webhook")),
		"no warning while the webhook is on"
	);
	assert_eq!(disable(&env, &["--yes"]).0, Some(0));
	let warnings = check(&env);
	assert!(
		warnings
			.iter()
			.any(|w| w.contains("alert \"spool\"") && w.contains("enabled = false")),
		"{warnings:?}"
	);
}

#[test]
fn unsetting_a_webhook_an_alert_posts_to_is_refused_by_policy() {
	let env = env(WITH_ALERT);
	let before = text(&env);
	let output = epistle(
		&["webhook", "--config", &env.config, "unset", "--json"],
		b"",
	);
	assert_eq!(output.status.code(), Some(3));
	assert!(output.stdout.is_empty());
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("alert \"spool\" posts to the webhook"),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(text(&env) == before, "a refused unset wrote the file");
}
