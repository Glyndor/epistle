//! `epistle limits` sets the minimum transfer rate of a message
//! transaction and its grace period, each validated, and shows them.

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
fn limits(file: &Path, args: &[&str]) -> (ExitCode, String) {
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

fn shown(file: &Path) -> String {
	let (code, printed) = limits(file, &["show"]);
	assert_eq!(code, ExitCode::SUCCESS);
	printed
}

#[test]
fn the_rate_floor_and_its_grace_are_set_and_unset() {
	let (_dir, file) = super::tests_config::config_file();
	for (key, value, field) in [
		("min-data-rate", "20k", "min_data_rate = 20480"),
		("data-rate-grace", "5m", "data_rate_grace = 300"),
	] {
		let (code, printed) = limits(file.path(), &["set", key, value]);
		assert_eq!(code, ExitCode::SUCCESS, "{key}: {printed}");
		let text = std::fs::read_to_string(file.path()).expect("config");
		assert!(text.contains(field), "{field} missing from {text}");
	}
	let printed = shown(file.path());
	for line in [
		"min-data-rate\t20480 bytes per second\tconfigured",
		"data-rate-grace\t300 seconds\tconfigured",
	] {
		assert!(
			printed.lines().any(|l| l == line),
			"{line} missing: {printed}"
		);
	}
	for key in ["min-data-rate", "data-rate-grace"] {
		let (code, _) = limits(file.path(), &["unset", key]);
		assert_eq!(code, ExitCode::SUCCESS);
	}
	let text = std::fs::read_to_string(file.path()).expect("config");
	assert!(!text.contains("data_rate"), "{text}");
}

#[test]
fn the_defaults_and_a_floor_turned_off_are_shown() {
	let (_dir, file) = super::tests_config::config_file();
	let printed = shown(file.path());
	for line in [
		"min-data-rate\t10240 bytes per second\tdefault",
		"data-rate-grace\t120 seconds\tdefault",
	] {
		assert!(
			printed.lines().any(|l| l == line),
			"{line} missing: {printed}"
		);
	}
	let config = Config::load(file.path()).expect("config");
	assert_eq!(
		show_json(&config)["min-data-rate"],
		serde_json::json!({"value": 10240, "unit": "bytes-per-second", "source": "default"})
	);
	assert_eq!(
		show_json(&config)["data-rate-grace"],
		serde_json::json!({"value": 120, "unit": "seconds", "source": "default"})
	);
	let (code, _) = limits(file.path(), &["set", "min-data-rate", "0"]);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		shown(file.path())
			.lines()
			.any(|l| l == "min-data-rate\tdisabled\tconfigured"),
		"0 turns the floor off"
	);
	let config = Config::load(file.path()).expect("config");
	assert_eq!(
		show_json(&config)["min-data-rate"],
		serde_json::json!({"value": null, "unit": "bytes-per-second", "source": "configured"})
	);
}

#[test]
fn a_json_set_reports_the_parsed_rate() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "--json", "min-data-rate", "16k"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	// The JSON object comes first; the restart notice follows it.
	let object = printed.lines().next().expect("a payload line");
	let payload: serde_json::Value = serde_json::from_str(object).expect("json payload");
	assert_eq!(payload["key"], "min-data-rate");
	assert_eq!(payload["value"], 16_384_u64);
}

#[test]
fn an_unsound_floor_or_grace_is_refused() {
	for (args, field) in [
		(["set", "data-rate-grace", "0"], "data_rate_grace"),
		(["set", "data-rate-grace", "2h"], "data_rate_grace"),
		(["set", "min-data-rate", "2G"], "min_data_rate"),
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
