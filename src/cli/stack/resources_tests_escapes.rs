//! Text `stack resources set` prints comes partly from compose.yaml and
//! the command line: control characters in it are escaped, never sent to
//! the terminal.

use std::process::ExitCode;

use serde_json::Value;

use super::{ResourcesCli, run};

/// Whether `text` carries a byte a terminal acts on.
fn has_control(text: &str) -> bool {
	text.chars().any(char::is_control)
}

#[test]
fn the_change_report_never_echoes_control_characters() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"mem_limit":"1g\u001b]0;x\u0007","pids_limit":5}}}"#,
	)
	.expect("compose");
	let mut out = Vec::new();
	let action = Some(ResourcesCli::Set {
		service: "mail".to_string(),
		memory: Some("2g".to_string()),
		pids: None,
	});
	assert_eq!(
		run(&compose, 25 << 20, action, false, &mut out),
		ExitCode::SUCCESS
	);
	let printed = String::from_utf8(out).expect("utf8");
	assert_eq!(
		printed.lines().next(),
		Some("mail: memory 1g\\u{1b}]0;x\\u{7} -> 2g"),
		"{:?}",
		printed.escape_debug().to_string()
	);
}

#[test]
fn refusals_never_echo_control_characters() {
	let dir = tempfile::tempdir().expect("tempdir");
	let text = crate::cli::init::rendered_for_tests(dir.path(), None);
	let mut document: Value = serde_json::from_str(&text).expect("json");
	document["x-epistle-resources"] = serde_json::json!({"clamav": {"\u{1b}[2J": 1}});
	let refusals = [
		super::set_limits(&text, "web\u{1b}[2J", Some("1g"), None),
		super::set_limits(&document.to_string(), "clamav", Some("2g"), None),
	];
	for refused in refusals {
		let error = refused.map(|_| ()).expect_err("refused");
		assert!(
			!has_control(&error),
			"{:?}",
			error.escape_debug().to_string()
		);
	}
}
