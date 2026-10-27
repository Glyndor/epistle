//! `epistle limits` sets the junk-command limit and the session lifetime
//! of the SMTP listeners, each validated, and shows them.

use std::process::ExitCode;

use clap::Parser;

use super::*;

#[derive(Parser)]
struct Limits {
	#[command(subcommand)]
	action: Action,
}

/// Run `epistle limits <args>` against `file`; returns the exit code and
/// what was printed on both streams.
pub(super) fn limits(file: &Path, args: &[&str]) -> (ExitCode, String) {
	let parsed = Limits::try_parse_from(std::iter::once("limits").chain(args.iter().copied()));
	assert!(parsed.is_ok(), "`limits {}` must parse", args.join(" "));
	let mut out = Vec::new();
	let mut status = Vec::new();
	let code = run_with_restart(
		file,
		parsed.expect("parsed").action,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	);
	let mut printed = String::from_utf8(out).expect("utf8");
	printed.push_str(&String::from_utf8(status).expect("utf8"));
	(code, printed)
}

pub(super) fn shown(file: &Path) -> String {
	let (code, printed) = limits(file, &["show"]);
	assert_eq!(code, ExitCode::SUCCESS);
	printed
}

pub(super) fn assert_shown(file: &Path, lines: &[&str]) {
	let printed = shown(file);
	for line in lines {
		assert!(
			printed.lines().any(|l| l == *line),
			"{line} missing: {printed}"
		);
	}
}

#[test]
fn both_limits_are_set_shown_and_unset() {
	let (_dir, file) = super::tests_config::config_file();
	for (key, value, field) in [
		("junk-command-limit", "50", "junk_command_limit = 50"),
		("max-session-time", "1h", "max_session_time = 3600"),
	] {
		let (code, printed) = limits(file.path(), &["set", key, value]);
		assert_eq!(code, ExitCode::SUCCESS, "{key}: {printed}");
		let text = std::fs::read_to_string(file.path()).expect("config");
		assert!(text.contains(field), "{field} missing from {text}");
	}
	assert_shown(
		file.path(),
		&[
			"junk-command-limit\t50\tconfigured\tadjustable\tno standard mandate",
			"max-session-time\t3600 seconds\tconfigured\tadjustable\tno standard mandate",
		],
	);
	for key in ["junk-command-limit", "max-session-time"] {
		let (code, _) = limits(file.path(), &["unset", key]);
		assert_eq!(code, ExitCode::SUCCESS);
	}
	let text = std::fs::read_to_string(file.path()).expect("config");
	assert!(
		!text.contains("junk_command_limit") && !text.contains("max_session_time"),
		"{text}"
	);
}

#[test]
fn the_defaults_and_limits_turned_off_are_shown() {
	let (_dir, file) = super::tests_config::config_file();
	assert_shown(
		file.path(),
		&[
			"junk-command-limit\t100\tdefault\tadjustable\tno standard mandate",
			"max-session-time\t1800 seconds\tdefault\tadjustable\tno standard mandate",
		],
	);
	let config = Config::load(file.path()).expect("config");
	assert_eq!(
		show_json(&config)["junk-command-limit"],
		serde_json::json!({"value": 100, "unit": "count", "source": "default", "kind": "adjustable", "class": "own", "bounds": null, "reference": "no standard mandate"})
	);
	assert_eq!(
		show_json(&config)["max-session-time"],
		serde_json::json!({"value": 1800, "unit": "seconds", "source": "default", "kind": "adjustable", "class": "own", "bounds": null, "reference": "no standard mandate"})
	);
	for key in ["junk-command-limit", "max-session-time"] {
		let (code, _) = limits(file.path(), &["set", key, "0"]);
		assert_eq!(code, ExitCode::SUCCESS);
	}
	assert_shown(
		file.path(),
		&[
			"junk-command-limit\tdisabled\tconfigured\tadjustable\tno standard mandate",
			"max-session-time\tdisabled\tconfigured\tadjustable\tno standard mandate",
		],
	);
	let config = Config::load(file.path()).expect("config");
	assert_eq!(
		show_json(&config)["junk-command-limit"],
		serde_json::json!({"value": null, "unit": "count", "source": "configured", "kind": "adjustable", "class": "own", "bounds": null, "reference": "no standard mandate"})
	);
	assert_eq!(
		show_json(&config)["max-session-time"],
		serde_json::json!({"value": null, "unit": "seconds", "source": "configured", "kind": "adjustable", "class": "own", "bounds": null, "reference": "no standard mandate"})
	);
}

#[test]
fn a_json_set_reports_the_parsed_lifetime() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "--json", "max-session-time", "45m"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	let object = printed.lines().next().expect("a payload line");
	let payload: serde_json::Value = serde_json::from_str(object).expect("json payload");
	assert_eq!(payload["key"], "max-session-time");
	assert_eq!(payload["value"], 2700_u64);
}

#[test]
fn an_unsound_limit_is_refused_and_not_saved() {
	for (args, field) in [
		(["set", "junk-command-limit", "5"], "junk_command_limit"),
		(["set", "junk-command-limit", "20000"], "junk_command_limit"),
		(["set", "max-session-time", "30"], "max_session_time"),
		(["set", "max-session-time", "2d"], "max_session_time"),
	] {
		let (_dir, file) = super::tests_config::config_file();
		let before = std::fs::read_to_string(file.path()).expect("config");
		let (code, printed) = limits(file.path(), &args);
		assert_eq!(code, ExitCode::FAILURE, "{args:?} must be refused");
		assert!(
			printed.contains(field),
			"the refusal names {field}: {printed}"
		);
		let after = std::fs::read_to_string(file.path()).expect("config");
		assert_eq!(before, after, "a refused value is not saved");
	}
}
