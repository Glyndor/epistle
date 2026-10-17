//! `epistle limits` reads and sets the outbound queue's conversation caps
//! and its backoff, in the `[queue]` table, each validated.

use std::process::ExitCode;

use clap::Parser;

use super::*;

#[derive(Parser)]
struct Limits {
	#[command(subcommand)]
	action: Action,
}

fn limits(file: &Path, args: &[&str]) -> (ExitCode, String) {
	let parsed = Limits::try_parse_from(std::iter::once("limits").chain(args.iter().copied()))
		.expect("parse");
	let mut out = Vec::new();
	let mut status = Vec::new();
	let code = run_with_restart(file, parsed.action, false, &mut out, &mut status, |_, _| {
		ExitCode::SUCCESS
	});
	let mut printed = String::from_utf8(out).expect("utf8");
	printed.push_str(&String::from_utf8(status).expect("utf8"));
	(code, printed)
}

#[test]
fn the_queue_caps_and_backoff_are_set_in_the_queue_table() {
	let (_dir, file) = super::tests_config::config_file();
	for (key, value) in [
		("queue-concurrency", "16"),
		("queue-per-domain-concurrency", "4"),
		("queue-backoff", "2m, 10m,1h"),
	] {
		let (code, printed) = limits(file.path(), &["set", key, value]);
		assert_eq!(code, ExitCode::SUCCESS, "{key}: {printed}");
	}
	let config = Config::load(file.path()).expect("config");
	assert_eq!(
		(
			config.queue.concurrency,
			config.queue.per_domain_concurrency
		),
		(16, 4)
	);
	assert_eq!(config.queue.backoff_steps, [120, 600, 3600]);

	let mut shown = Vec::new();
	show(&config, &mut shown).expect("show");
	let shown = String::from_utf8(shown).expect("utf8");
	assert!(
		shown.contains("queue-concurrency\t16\tconfigured\n"),
		"{shown}"
	);
	assert!(
		shown.contains("queue-backoff\t120,600,3600 seconds\tconfigured\n"),
		"{shown}"
	);
	let json = show_json(&config);
	assert_eq!(
		json["queue-backoff"],
		serde_json::json!({"value": [120, 600, 3600], "unit": "seconds", "source": "configured"})
	);
	assert_eq!(json["queue-per-domain-concurrency"]["value"], 4);

	for key in [
		"queue-concurrency",
		"queue-per-domain-concurrency",
		"queue-backoff",
	] {
		let (code, printed) = limits(file.path(), &["unset", key]);
		assert_eq!(code, ExitCode::SUCCESS, "{key}: {printed}");
	}
	let config = Config::load(file.path()).expect("config");
	assert_eq!(config.queue.concurrency, 8);
	assert_eq!(config.queue.backoff_steps, [60, 300, 900, 3600]);
}

#[test]
fn unsound_queue_caps_and_backoff_are_refused_without_writing() {
	let (_dir, file) = super::tests_config::config_file();
	let before = std::fs::read_to_string(file.path()).expect("config");
	for (key, value) in [
		("queue-concurrency", "0"),
		("queue-concurrency", "1025"),
		("queue-per-domain-concurrency", "9"),
		("queue-backoff", "0"),
		("queue-backoff", "2d"),
		("queue-backoff", "1m,,5m"),
		("queue-backoff", &"1m,".repeat(17)[..50]),
	] {
		let (code, printed) = limits(file.path(), &["set", key, value]);
		assert_ne!(code, ExitCode::SUCCESS, "{key} {value}: {printed}");
		assert!(printed.starts_with("cannot update limits: "), "{printed}");
	}
	let (code, printed) = limits(
		file.path(),
		&["set", "queue-backoff", "--domain", "a.example", "1m"],
	);
	assert_ne!(code, ExitCode::SUCCESS, "{printed}");
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("config"),
		before
	);
}

#[test]
fn changing_a_queue_cap_asks_for_a_restart() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "queue-concurrency", "12"]);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(printed, "limits saved\nThe server must be restarted.\n");
}
