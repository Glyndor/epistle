//! `epistle warmup` against temporary data directories.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cli::{Cli, Command};
use clap::Parser;

/// Midnight UTC of 2025-10-14.
pub(super) const MIDNIGHT: u64 = 20_375 * 86_400;

fn parse(args: &[&str]) -> Result<WarmupCli, String> {
	let mut argv = vec!["epistle", "warmup"];
	argv.extend(args);
	match Cli::try_parse_from(argv) {
		Ok(Cli {
			command: Command::Warmup { action, .. },
			..
		}) => Ok(action),
		Ok(_) => Err("not a warmup command".into()),
		Err(error) => Err(error.to_string()),
	}
}

pub(super) fn run_args(dir: &Path, log_days: u64, args: &[&str]) -> (u8, String) {
	let action = parse(args).expect("parse");
	let mut out = Vec::new();
	let code = run(dir, None, log_days, &[], action, MIDNIGHT + 3600, &mut out);
	let code = [0u8, 1, 2]
		.into_iter()
		.find(|known| code == ExitCode::from(*known))
		.expect("a known exit code");
	(code, String::from_utf8(out).expect("utf8"))
}

#[test]
fn bad_input_is_refused_before_anything_is_written() {
	for (args, why) in [
		(
			&["set", "hotmail", "--cap", "10"][..],
			"unknown group \"hotmail\"",
		),
		(&["set", "gmail", "--cap", "0"][..], "from 1 to 1000000"),
		(
			&["set", "gmail", "--cap", "1000001"][..],
			"from 1 to 1000000",
		),
		(&["set", "gmail", "--cap", "-5"][..], "unexpected argument"),
		(&["set", "gmail"][..], "--cap <CAP>"),
		(
			&["set", "gmail", "--cap", "10", "--next"][..],
			"cannot be used with",
		),
		(&["reset"][..], "<GROUP>"),
	] {
		let error = parse(args).expect_err("refused");
		assert!(error.contains(why), "{args:?}: {error}");
	}
}

#[test]
fn a_change_without_yes_off_a_terminal_is_refused_and_not_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	for args in [
		&["enable"][..],
		&["set", "gmail", "--cap", "200"][..],
		&["set", "gmail", "--next"][..],
		&["reset", "gmail"][..],
	] {
		let (code, out) = run_args(dir.path(), 30, args);
		assert_eq!((code, out.as_str()), (2, ""), "{args:?}");
	}
	assert!(!settings::path(dir.path()).exists());
	// `disable` on an install that never enabled it changes nothing, so
	// there is nothing to confirm.
	assert_eq!(
		run_args(dir.path(), 30, &["disable"]),
		(0, "warm-up disable: unchanged\n".to_string())
	);
}

#[test]
fn enable_writes_a_private_file_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(
		run_args(dir.path(), 30, &["enable", "--yes"]),
		(0, "warm-up enable: saved\n".to_string())
	);
	let mode = std::fs::metadata(settings::path(dir.path()))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o777, 0o600);
	assert_eq!(
		run_args(dir.path(), 30, &["enable"]),
		(0, "warm-up enable: unchanged\n".to_string())
	);
	assert_eq!(
		settings::load(dir.path()).expect("load"),
		Some(Settings {
			enabled: true,
			..Settings::default()
		})
	);
}

#[test]
fn enable_is_refused_while_the_delivery_log_is_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(
		run_args(dir.path(), 0, &["enable", "--yes"]),
		(2, String::new())
	);
	assert!(!settings::path(dir.path()).exists());
}

#[test]
fn each_change_reports_itself_in_json() {
	let dir = tempfile::tempdir().expect("tempdir");
	let runs = [
		(
			&["enable", "--yes", "--json"][..],
			r#"{"action":"enable","enabled":true,"order":null,"paused":false,"result":"saved"}"#,
		),
		(
			&["pause", "--json"][..],
			r#"{"action":"pause","enabled":true,"order":null,"paused":true,"result":"saved"}"#,
		),
		(
			&["set", "gmail", "--cap", "200", "--yes", "--json"][..],
			r#"{"action":"set","enabled":true,"order":{"action":{"set":{"cap":200}},"group":"gmail","seq":1},"paused":true,"result":"saved"}"#,
		),
		(
			&["set", "outlook", "--next", "--yes", "--json"][..],
			r#"{"action":"next","enabled":true,"order":{"action":"next","group":"outlook","seq":2},"paused":true,"result":"saved"}"#,
		),
		(
			&["reset", "gmail", "--yes", "--json"][..],
			r#"{"action":"reset","enabled":true,"order":{"action":"reset","group":"gmail","seq":3},"paused":true,"result":"saved"}"#,
		),
		(
			&["resume", "--json"][..],
			r#"{"action":"resume","enabled":true,"order":null,"paused":false,"result":"saved"}"#,
		),
		(
			&["disable", "--yes", "--json"][..],
			r#"{"action":"disable","enabled":false,"order":null,"paused":false,"result":"saved"}"#,
		),
	];
	for (args, want) in runs {
		assert_eq!(
			run_args(dir.path(), 30, args),
			(0, format!("{want}\n")),
			"{args:?}"
		);
	}
}

#[test]
fn a_settings_file_others_could_write_is_not_built_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	settings::save(dir.path(), &Settings::default()).expect("save");
	std::fs::set_permissions(
		settings::path(dir.path()),
		std::fs::Permissions::from_mode(0o666),
	)
	.expect("chmod");
	assert_eq!(
		run_args(dir.path(), 30, &["enable", "--yes"]),
		(2, String::new())
	);
	assert_eq!(run_args(dir.path(), 30, &["status"]).0, 1);
}
