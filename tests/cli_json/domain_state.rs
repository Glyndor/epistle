//! `domain disable` and `domain enable`: the switch is the `disabled_domains`
//! array of the configuration file, edited in place.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

fn run(config: &str, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["domain", "--config", config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

fn text(env: &Env) -> String {
	std::fs::read_to_string(&env.config).expect("read config")
}

fn with_second_domain() -> Env {
	let env = env("# kept across edits\n");
	assert_eq!(run(&env.config, &["add", "example.net"]).0, 0);
	env
}

#[test]
fn disable_then_enable_a_domain() {
	let env = with_second_domain();
	let disabled = json!({
		"result": "saved", "action": "disable", "domain": "example.net",
		"enabled": false, "reload": "restart-needed",
	});
	assert_eq!(
		run(&env.config, &["disable", "example.net", "--yes"]),
		(0, disabled)
	);
	assert!(
		text(&env).contains("disabled_domains = [\"example.net\"]"),
		"config after disable:\n{}",
		text(&env)
	);
	assert!(text(&env).contains("# kept across edits"));

	let again = run(&env.config, &["disable", "example.net", "--yes"]);
	assert_eq!(again.1["result"], "unchanged");

	let enabled = json!({
		"result": "saved", "action": "enable", "domain": "example.net",
		"enabled": true, "reload": "restart-needed",
	});
	assert_eq!(run(&env.config, &["enable", "example.net"]), (0, enabled));
	assert!(
		text(&env).contains("disabled_domains = []"),
		"example.net must leave disabled_domains:\n{}",
		text(&env)
	);
	assert_eq!(
		run(&env.config, &["enable", "example.net"]).1["result"],
		"unchanged"
	);
}

#[test]
fn list_and_show_say_whether_a_domain_is_enabled() {
	let env = with_second_domain();
	assert_eq!(run(&env.config, &["disable", "example.net", "--yes"]).0, 0);
	let (_, list) = run(&env.config, &["list"]);
	let enabled: Vec<(String, bool)> = list
		.as_array()
		.expect("array")
		.iter()
		.map(|row| {
			(
				row["domain"].as_str().expect("domain").to_string(),
				row["enabled"].as_bool().expect("enabled flag"),
			)
		})
		.collect();
	assert_eq!(
		enabled,
		vec![("example.org".into(), true), ("example.net".into(), false)]
	);
	let (_, show) = run(&env.config, &["show", "example.net"]);
	assert_eq!(show["enabled"], false);
}

#[test]
fn a_dry_run_changes_nothing_and_shows_the_diff() {
	let env = with_second_domain();
	let before = text(&env);
	let (code, value) = run(&env.config, &["disable", "example.net", "--dry-run"]);
	assert_eq!((code, value["result"].as_str()), (0, Some("dry-run")));
	assert!(
		value["diff"]
			.as_str()
			.is_some_and(|diff| diff.contains("+disabled_domains = [\"example.net\"]")),
		"diff: {}",
		value["diff"]
	);
	assert_eq!(text(&env), before);
}

#[test]
fn disabling_without_yes_off_a_terminal_is_refused() {
	let env = with_second_domain();
	let before = text(&env);
	let output = epistle(
		&[
			"domain",
			"--config",
			&env.config,
			"disable",
			"example.net",
			"--json",
		],
		b"",
	);
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("--yes"),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(text(&env), before);
}

#[test]
fn an_unknown_domain_is_refused_and_nothing_is_printed() {
	let env = env("");
	for action in ["disable", "enable"] {
		let output = epistle(
			&[
				"domain",
				"--config",
				&env.config,
				action,
				"nowhere.example",
				"--json",
			],
			b"",
		);
		assert_eq!(output.status.code(), Some(2), "{action}");
		assert!(output.stdout.is_empty(), "{action}");
		assert_eq!(
			String::from_utf8_lossy(&output.stderr).trim_end(),
			"error: domain nowhere.example is not configured",
			"{action}"
		);
	}
}

#[test]
fn the_last_enabled_domain_cannot_be_disabled_while_the_server_listens() {
	let env = env("[[listeners]]\nkind = \"smtp\"\n");
	let before = text(&env);
	let output = epistle(
		&[
			"domain",
			"--config",
			&env.config,
			"disable",
			"example.org",
			"--yes",
			"--json",
		],
		b"",
	);
	assert_eq!(output.status.code(), Some(3));
	assert!(output.stdout.is_empty());
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("keep one domain enabled"),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(text(&env), before);
}

#[test]
fn removing_a_disabled_domain_drops_it_from_the_list_too() {
	let env = with_second_domain();
	assert_eq!(run(&env.config, &["disable", "example.net", "--yes"]).0, 0);
	let (code, value) = run(&env.config, &["remove", "example.net", "--yes"]);
	assert_eq!(
		(code, value["result"].as_str()),
		(0, Some("saved")),
		"{value}"
	);
	assert!(
		!text(&env).contains("example.net"),
		"example.net is still in the file:\n{}",
		text(&env)
	);
}

#[test]
fn the_text_list_marks_a_disabled_domain() {
	let env = with_second_domain();
	let list = |env: &Env| {
		let output = epistle(&["domain", "--config", &env.config, "list"], b"");
		assert_eq!(output.status.code(), Some(0));
		String::from_utf8_lossy(&output.stdout).into_owned()
	};
	assert!(!list(&env).contains("disabled"), "{}", list(&env));
	assert_eq!(run(&env.config, &["disable", "example.net", "--yes"]).0, 0);
	let text = list(&env);
	let line = text
		.lines()
		.find(|line| line.contains("example.net"))
		.expect("row");
	assert!(line.contains("example.net (disabled)"), "{text}");
	let other = text
		.lines()
		.find(|line| line.contains("example.org"))
		.expect("row");
	assert!(!other.contains("disabled"), "{text}");
}

fn queue_from(env: &Env, sender: &str) {
	epistle::storage::FsSpool::open(&env.data_dir())
		.expect("spool")
		.store(
			&epistle::smtp::session::AcceptedMessage {
				reverse_path: sender.into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				..Default::default()
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
}

#[test]
fn disabling_says_how_much_queued_mail_still_goes_out_from_the_domain() {
	let env = with_second_domain();
	queue_from(&env, "alice@example.net");
	queue_from(&env, "Carol@Example.NET");
	queue_from(&env, "dave@example.org");
	let output = epistle(
		&[
			"domain",
			"--config",
			&env.config,
			"disable",
			"example.net",
			"--yes",
			"--json",
		],
		b"",
	);
	assert_eq!(output.status.code(), Some(0));
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("2 queued messages have a sender in example.net and are still delivered"),
		"{stderr}"
	);
	// Nothing to say when nothing is queued from the domain.
	let quiet = with_second_domain();
	queue_from(&quiet, "dave@example.org");
	let output = epistle(
		&[
			"domain",
			"--config",
			&quiet.config,
			"disable",
			"example.net",
			"--yes",
			"--json",
		],
		b"",
	);
	assert!(!String::from_utf8_lossy(&output.stderr).contains("queued"));
}
