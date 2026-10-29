//! `epistle limits` sets the outbound retry schedule: the first wait, the
//! cap, and the age of the delay warning, each validated.

use std::process::ExitCode;

use clap::Parser;

use super::*;

#[derive(Parser)]
struct Limits {
	#[command(subcommand)]
	action: Action,
}

/// Run `epistle limits <args>` against `file`; returns the exit code and
/// what was printed on the status stream.
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

#[test]
fn the_retry_schedule_is_set_like_the_give_up_window() {
	let (_dir, file) = super::config::config_file();
	for (key, value, field) in [
		("queue-retry-base", "2m", "queue_retry_base_secs = 120"),
		("queue-retry-cap", "2h", "queue_retry_cap_secs = 7200"),
		(
			"queue-delay-warning",
			"1d",
			"queue_delay_warning_secs = 86400",
		),
	] {
		let (code, printed) = limits(file.path(), &["set", key, value]);
		assert_eq!(code, ExitCode::SUCCESS, "{key}: {printed}");
		let text = std::fs::read_to_string(file.path()).expect("config");
		assert!(text.contains(field), "{field} missing from {text}");
	}
	let (code, _) = limits(file.path(), &["unset", "queue-retry-base"]);
	assert_eq!(code, ExitCode::SUCCESS);
	let text = std::fs::read_to_string(file.path()).expect("config");
	assert!(!text.contains("queue_retry_base_secs"), "{text}");
}

#[test]
fn an_unsound_retry_schedule_is_refused() {
	for (args, field) in [
		// Retrying faster than once a minute hammers the remote.
		(["set", "queue-retry-base", "30s"], "queue_retry_base_secs"),
		// The cap cannot be below the first wait (default 1 minute).
		(["set", "queue-retry-cap", "30s"], "queue_retry_cap_secs"),
		// A warning after the give-up window (default 5 days) never comes.
		(
			["set", "queue-delay-warning", "6d"],
			"queue_delay_warning_secs",
		),
	] {
		let (_dir, file) = super::config::config_file();
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

#[test]
fn show_gives_today_schedule_as_the_default() {
	let (_dir, file) = super::config::config_file();
	let (code, printed) = limits(file.path(), &["show"]);
	assert_eq!(code, ExitCode::SUCCESS);
	for line in [
		"queue-retry-base\t60 seconds\tdefault\trecommended\tRFC 5321 §4.5.4.1 (30 minutes recommended)",
		"queue-retry-cap\t3600 seconds\tdefault\tadjustable\tno standard mandate",
		"queue-delay-warning\t14400 seconds\tdefault\tadjustable\tno standard mandate",
	] {
		assert!(
			printed.lines().any(|l| l == line),
			"{line} missing: {printed}"
		);
	}
}
