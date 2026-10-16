//! `epistle attachments` with the real binary: `policy show|set|unset` and
//! `check` print one JSON document under `--json`, `check --strict` exits 3
//! for a verdict the server would not deliver, and a refusal leaves stdout
//! empty.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

/// A PE header declared as a PDF: quarantined by the default `quarantine`
/// policy.
const DISGUISED: &str = "From: x@example.net\r\nTo: alice@example.org\r\nSubject: invoice\r\n\
	MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
	Content-Type: text/plain\r\n\r\nsee attached\r\n--b\r\n\
	Content-Type: application/pdf; name=invoice.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n\
	TVqQAAMAAAAEAAAA\r\n--b--\r\n";

fn eml(env: &Env, text: &str) -> String {
	let path = env.dir.path().join("message.eml");
	std::fs::write(&path, text).expect("write eml");
	path.to_string_lossy().into_owned()
}

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["attachments", "--config", env.config.as_str()];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

#[test]
fn policy_show_is_one_object() {
	let env = env("[attachments]\nmode = \"reject\"\nblock_extensions = [\"docm\"]\n");
	let (code, value) = run(&env, &["policy", "show"]);
	assert_eq!(code, 0);
	assert_eq!(value["mode"], "reject");
	assert_eq!(value["block-extensions"], json!(["docm"]));
	assert_eq!(value["macros"], "flag");
}

#[test]
fn policy_set_and_unset_report_the_change() {
	let env = env("");
	assert_eq!(
		run(&env, &["policy", "set", "block-extensions", "DOCM", "xlsm"]),
		(
			0,
			json!({
				"result": "saved", "action": "set", "key": "block-extensions",
				"value": ["docm", "xlsm"], "reload": "restart-needed",
			})
		)
	);
	assert_eq!(
		run(&env, &["policy", "unset", "block-extensions"]),
		(
			0,
			json!({
				"result": "saved", "action": "unset", "key": "block-extensions",
				"reload": "restart-needed",
			})
		)
	);
	assert_eq!(
		run(&env, &["policy", "unset", "block-extensions"]).1["result"],
		"unchanged"
	);
}

#[test]
fn a_dry_run_prints_the_diff_inside_the_object() {
	let env = env("");
	let before = std::fs::read_to_string(&env.config).expect("config");
	let (code, value) = run(&env, &["policy", "set", "mode", "reject", "--dry-run"]);
	assert_eq!(code, 0);
	assert_eq!(value["result"], "dry-run");
	assert!(
		value["diff"].as_str().is_some_and(|d| d.contains("reject")),
		"{value}"
	);
	assert_eq!(
		std::fs::read_to_string(&env.config).expect("config"),
		before
	);
}

#[test]
fn a_refused_change_leaves_stdout_empty() {
	let env = env("");
	let output = epistle(
		&[
			"attachments",
			"--config",
			&env.config,
			"policy",
			"set",
			"allow-extensions",
			"exe",
			"--json",
		],
		b"",
	);
	assert_ne!(output.status.code(), Some(0));
	assert!(output.stdout.is_empty());
}

#[test]
fn check_prints_one_object_and_exits_0_without_strict() {
	let env = env("[attachments]\nmode = \"quarantine\"\n");
	let path = eml(&env, DISGUISED);
	let (code, value) = run(&env, &["check", &path]);
	assert_eq!(code, 0);
	assert_eq!(value["verdict"], "quarantine");
	assert_eq!(value["submission"], "refused");
}

#[test]
fn check_strict_exits_3_and_still_prints_the_object() {
	let env = env("[attachments]\nmode = \"quarantine\"\n");
	let path = eml(&env, DISGUISED);
	let (code, value) = run(&env, &["check", &path, "--strict"]);
	assert_eq!(code, 3);
	assert_eq!(value["verdict"], "quarantine");
}

#[test]
fn check_strict_exits_0_for_a_clean_message() {
	let env = env("[attachments]\nmode = \"quarantine\"\n");
	let path = eml(&env, "From: x@example.net\r\nSubject: hi\r\n\r\nhello\r\n");
	let (code, value) = run(&env, &["check", &path, "--strict"]);
	assert_eq!((code, &value["verdict"]), (0, &json!("deliver")));
}

#[test]
fn check_of_a_missing_file_leaves_stdout_empty() {
	let env = env("");
	let output = epistle(
		&[
			"attachments",
			"--config",
			&env.config,
			"check",
			"/nonexistent/none.eml",
			"--json",
		],
		b"",
	);
	assert_eq!(output.status.code(), Some(1));
	assert!(output.stdout.is_empty());
}
