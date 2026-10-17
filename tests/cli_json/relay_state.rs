//! `relay enable` and `relay disable`, and `enabled` in `relay show` and `list`.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

const RULES: &str = "# keep me
[[transport]]
kind = \"relay\"
host = \"relay.example.net\"
port = 587
starttls = true
username = \"mailer\"
password = \"relay-password-value\"

[[transport]]
domain = \"example.com\"
kind = \"relay\"
host = \"other.example.net\"
port = 25
";

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["relay", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

fn text(env: &Env) -> String {
	std::fs::read_to_string(&env.config).expect("read config")
}

#[test]
fn disable_then_enable_the_default_route() {
	let env = env(RULES);
	let disabled = json!({
		"result": "saved", "action": "disable", "account": null, "domain": null,
		"enabled": false, "reload": "restart-needed",
	});
	assert_eq!(run(&env, &["disable", "--yes"]), (0, disabled));
	assert!(text(&env).contains("enabled = false"), "{}", text(&env));
	assert!(text(&env).contains("# keep me"));
	assert_eq!(text(&env).matches("enabled = false").count(), 1);
	assert_eq!(run(&env, &["disable", "--yes"]).1["result"], "unchanged");

	let (_, shown) = run(&env, &["show"]);
	assert_eq!(shown["enabled"], false);
	assert_eq!(shown["host"], "relay.example.net");
	assert_eq!(shown["password"], "set");
	let (_, other) = run(&env, &["show", "--domain", "example.com"]);
	assert_eq!(other["enabled"], true, "the other rule stays on");

	let enabled = json!({
		"result": "saved", "action": "enable", "account": null, "domain": null,
		"enabled": true, "reload": "restart-needed",
	});
	assert_eq!(run(&env, &["enable"]), (0, enabled));
	assert!(!text(&env).contains("enabled"), "{}", text(&env));
	assert_eq!(run(&env, &["enable"]).1["result"], "unchanged");
}

#[test]
fn a_rule_is_switched_by_its_selector() {
	let env = env(RULES);
	let (code, value) = run(&env, &["disable", "--domain", "example.com", "--yes"]);
	assert_eq!((code, value["domain"].as_str()), (0, Some("example.com")));
	assert_eq!(
		run(&env, &["show", "--domain", "example.com"]).1["enabled"],
		false
	);
	assert_eq!(run(&env, &["show"]).1["enabled"], true);
	let (_, list) = run(&env, &["list"]);
	let flags: Vec<(String, bool)> = list
		.as_array()
		.expect("array")
		.iter()
		.map(|row| {
			(
				row["target"].as_str().expect("target").to_string(),
				row["enabled"].as_bool().expect("enabled"),
			)
		})
		.collect();
	assert_eq!(
		flags,
		vec![
			("default".into(), true),
			("domain:example.com".into(), false)
		]
	);
	let output = epistle(&["relay", "--config", &env.config, "list"], b"");
	assert!(
		String::from_utf8_lossy(&output.stdout)
			.contains("domain:example.com\tother.example.net:25\tstarttls=no\tauth=no\tdisabled\n"),
		"list: {}",
		String::from_utf8_lossy(&output.stdout)
	);
}

#[test]
fn updating_a_disabled_relay_leaves_it_disabled() {
	let env = env(RULES);
	assert_eq!(
		run(&env, &["disable", "--domain", "example.com", "--yes"]).0,
		0
	);
	let (code, _) = run(
		&env,
		&[
			"add",
			"--domain",
			"example.com",
			"--host",
			"new.example.net",
		],
	);
	assert_eq!(code, 0);
	let (_, shown) = run(&env, &["show", "--domain", "example.com"]);
	assert_eq!(
		(shown["host"].as_str(), shown["enabled"].as_bool()),
		(Some("new.example.net"), Some(false))
	);
}

#[test]
fn a_dry_run_changes_nothing_and_hides_the_password() {
	let env = env(RULES);
	let before = text(&env);
	let (code, value) = run(&env, &["disable", "--dry-run"]);
	assert!(
		!value.to_string().contains("relay-password-value"),
		"the password reached the diff"
	);
	assert_eq!((code, value["result"].as_str()), (0, Some("dry-run")));
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("+enabled = false")),
		"diff: {}",
		value["diff"]
	);
	assert!(!value.to_string().contains("relay-password-value"));
	assert!(text(&env) == before, "a dry run wrote the file");
}

#[test]
fn a_selector_without_a_relay_is_refused() {
	let env = env(RULES);
	for action in ["enable", "disable"] {
		let output = epistle(
			&[
				"relay",
				"--config",
				&env.config,
				action,
				"--domain",
				"nowhere.example",
				"--json",
			],
			b"",
		);
		assert_eq!(output.status.code(), Some(2), "{action}");
		assert!(output.stdout.is_empty(), "{action}");
		assert_eq!(
			String::from_utf8_lossy(&output.stderr).trim_end(),
			"error: no relay is configured for domain nowhere.example",
			"{action}"
		);
	}
}

fn disable_plain(env: &Env, extra: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["relay", "--config", &env.config, "disable"];
	full.extend_from_slice(extra);
	let output = epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

#[test]
fn disabling_a_relay_without_yes_off_a_terminal_is_refused() {
	let env = env(RULES);
	let before = text(&env);
	for extra in [vec![], vec!["--json"], vec!["--domain", "example.com"]] {
		let (code, stdout, stderr) = disable_plain(&env, &extra);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{extra:?}");
		assert!(stderr.contains("--yes"), "{stderr}");
		assert!(
			stderr.contains("directly") && stderr.contains("this server's own address"),
			"the warning must say the mail leaves directly: {stderr}"
		);
	}
	assert!(text(&env) == before, "a refused disable wrote the file");
}

#[test]
fn the_warning_names_the_rule_and_a_dry_run_asks_nothing() {
	let env = env(RULES);
	let (code, _, stderr) =
		disable_plain(&env, &["--domain", "example.com", "--dry-run", "--json"]);
	assert_eq!(code, Some(0), "{stderr}");
	assert!(stderr.contains("domain example.com"), "{stderr}");
	let (code, _, stderr) = disable_plain(&env, &["--domain", "example.com", "--yes", "--json"]);
	assert_eq!(code, Some(0), "{stderr}");
	assert!(
		stderr.contains("domain example.com") && stderr.contains("directly"),
		"{stderr}"
	);
}

#[test]
fn a_relay_that_is_already_off_is_not_asked_about_again() {
	let env = env(RULES);
	assert_eq!(run(&env, &["disable", "--yes"]).0, 0);
	let (code, stdout, stderr) = disable_plain(&env, &["--json"]);
	assert_eq!(code, Some(0), "{stderr}");
	assert!(stdout.contains("\"unchanged\""), "{stdout}");
	assert!(!stderr.contains("directly"), "{stderr}");
}
