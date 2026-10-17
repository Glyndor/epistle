//! `alert show`, `alert enable` and `alert disable`.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

const RULE: &str = "# keep me
[webhook]
url = \"https://hooks.example.net/in\"

[[alerts]]
name = \"spool\"
metric = \"accepted\"
op = \">\"
threshold = 100
window_secs = 300
webhook = true
cooldown_secs = 3600
";

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["alert", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

fn text(env: &Env) -> String {
	std::fs::read_to_string(&env.config).expect("read config")
}

fn row(enabled: bool) -> Value {
	json!({
		"name": "spool", "metric": "accepted", "op": ">", "threshold": 100,
		"window_secs": 300, "cooldown_secs": 3600, "webhook": true, "email": [],
		"enabled": enabled,
	})
}

#[test]
fn show_prints_one_rule() {
	let env = env(RULE);
	assert_eq!(run(&env, &["show", "spool"]), (0, row(true)));
	let output = epistle(&["alert", "--config", &env.config, "show", "spool"], b"");
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"name\tspool\nmetric\taccepted\nop\t>\nthreshold\t100\nwindow_secs\t300\n\
		 cooldown_secs\t3600\nwebhook\tyes\nemail\t-\nenabled\tyes\n"
	);
}

#[test]
fn disable_then_enable_a_rule() {
	let env = env(RULE);
	let disabled = json!({
		"result": "saved", "action": "disable", "alert": "spool",
		"enabled": false, "reload": "restart-needed",
	});
	assert_eq!(run(&env, &["disable", "spool"]), (0, disabled));
	assert!(text(&env).contains("enabled = false"), "{}", text(&env));
	assert!(text(&env).contains("# keep me"));
	assert_eq!(run(&env, &["disable", "spool"]).1["result"], "unchanged");
	assert_eq!(run(&env, &["show", "spool"]), (0, row(false)));
	let (_, list) = run(&env, &["list"]);
	assert_eq!(list, json!([row(false)]));
	let output = epistle(&["alert", "--config", &env.config, "list"], b"");
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"spool\taccepted > 100\twindow=300s\tcooldown=3600s\twebhook=yes\temail=-\tdisabled\n"
	);

	let enabled = json!({
		"result": "saved", "action": "enable", "alert": "spool",
		"enabled": true, "reload": "restart-needed",
	});
	assert_eq!(run(&env, &["enable", "spool"]), (0, enabled));
	assert!(!text(&env).contains("enabled"), "{}", text(&env));
	assert_eq!(run(&env, &["enable", "spool"]).1["result"], "unchanged");
}

#[test]
fn a_rule_written_as_an_inline_array_is_switched_off_in_place() {
	let env = env(
		"alerts = [{ name = \"spool\", metric = \"accepted\", op = \">\", threshold = 100, \
		 window_secs = 300, webhook = true, cooldown_secs = 3600 }]\n\
		 [webhook]\nurl = \"https://hooks.example.net/in\"\n",
	);
	assert_eq!(run(&env, &["disable", "spool"]).1["result"], "saved");
	assert_eq!(run(&env, &["show", "spool"]), (0, row(false)));
}

#[test]
fn a_dry_run_changes_nothing() {
	let env = env(RULE);
	let before = text(&env);
	let mut full = vec!["alert", "--config", &env.config, "disable", "spool"];
	full.extend_from_slice(&["--dry-run", "--json"]);
	let (code, value) = json(&epistle(&full, b""));
	assert_eq!((code, value["result"].as_str()), (0, Some("dry-run")));
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("+enabled = false")),
		"diff: {}",
		value["diff"]
	);
	assert_eq!(text(&env), before);
}

#[test]
fn an_unknown_rule_is_refused_by_every_action() {
	let env = env(RULE);
	for action in ["show", "enable", "disable"] {
		let output = epistle(
			&["alert", "--config", &env.config, action, "nope", "--json"],
			b"",
		);
		assert_eq!(output.status.code(), Some(2), "{action}");
		assert!(output.stdout.is_empty(), "{action}");
		assert_eq!(
			String::from_utf8_lossy(&output.stderr).trim_end(),
			"error: no alert named \"nope\"",
			"{action}"
		);
	}
}
