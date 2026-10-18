//! `epistle limits` sets the deadline and the connection caps of the mailbox
//! and HTTP listeners, each validated, and shows them.

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
fn the_preauth_deadline_is_shown_set_and_unset() {
	let (_dir, file) = super::tests_config::config_file();
	assert!(
		shown(file.path())
			.lines()
			.any(|line| line == "preauth-timeout\t60 seconds\tdefault")
	);
	let (code, printed) = limits(file.path(), &["set", "preauth-timeout", "2m"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	let text = std::fs::read_to_string(file.path()).expect("config");
	assert!(text.contains("preauth_timeout = 120"), "{text}");
	assert!(
		shown(file.path())
			.lines()
			.any(|line| line == "preauth-timeout\t120 seconds\tconfigured")
	);
	let (code, _) = limits(file.path(), &["unset", "preauth-timeout"]);
	assert_eq!(code, ExitCode::SUCCESS);
	let text = std::fs::read_to_string(file.path()).expect("config");
	assert!(!text.contains("preauth_timeout"), "{text}");
}

#[test]
fn an_unsound_preauth_deadline_is_refused_and_not_saved() {
	for value in ["4", "2h"] {
		let (_dir, file) = super::tests_config::config_file();
		let before = std::fs::read_to_string(file.path()).expect("config");
		let (code, printed) = limits(file.path(), &["set", "preauth-timeout", value]);
		assert_eq!(code, ExitCode::FAILURE, "{value} must be refused");
		assert!(printed.contains("preauth_timeout"), "{printed}");
		let after = std::fs::read_to_string(file.path()).expect("config");
		assert_eq!(before, after, "a refused value is not saved");
	}
}

#[test]
fn the_connection_caps_are_shown_set_and_unset() {
	let (_dir, file) = super::tests_config::config_file();
	for line in [
		"max-mailbox-connections-per-ip\t200\tdefault",
		"max-http-connections\t1024\tdefault",
		"max-http-connections-per-ip\t256\tdefault",
	] {
		assert!(shown(file.path()).lines().any(|l| l == line), "{line}");
	}
	for (key, value, field) in [
		(
			"max-mailbox-connections-per-ip",
			"500",
			"max_mailbox_connections_per_ip = 500",
		),
		("max-http-connections", "64", "max_http_connections = 64"),
		(
			"max-http-connections-per-ip",
			"8",
			"max_http_connections_per_ip = 8",
		),
	] {
		let (code, printed) = limits(file.path(), &["set", key, value]);
		assert_eq!(code, ExitCode::SUCCESS, "{key}: {printed}");
		let text = std::fs::read_to_string(file.path()).expect("config");
		assert!(text.contains(field), "{field} missing from {text}");
		let line = format!("{key}\t{value}\tconfigured");
		assert!(shown(file.path()).lines().any(|l| l == line), "{line}");
		let (code, _) = limits(file.path(), &["unset", key]);
		assert_eq!(code, ExitCode::SUCCESS);
		let text = std::fs::read_to_string(file.path()).expect("config");
		assert!(
			!text.contains(&field[..field.find(' ').expect("key")]),
			"{text}"
		);
	}
}
