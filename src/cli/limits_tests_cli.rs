use std::cell::Cell;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::CommandFactory;

use super::*;
use crate::cli::Cli;

#[test]
fn limits_commands_accept_defaults_and_config_before_or_after_action() {
	for args in [
		vec!["epistle", "limits", "show"],
		vec!["epistle", "limits", "set", "quota", "5G"],
		vec!["epistle", "limits", "unset", "queue-give-up"],
	] {
		let matches = Cli::command().try_get_matches_from(args.clone());
		assert_eq!(
			matches
				.as_ref()
				.ok()
				.and_then(|matches| matches.subcommand_matches("limits"))
				.and_then(|matches| matches.get_one::<PathBuf>("config"))
				.map(PathBuf::as_path),
			Some(Path::new("/etc/epistle/mail.toml")),
			"limits commands must parse with the packaged config default"
		);
		for position in [2, args.len()] {
			let mut custom = args.clone();
			custom.splice(position..position, ["--config", "/tmp/custom.toml"]);
			let matches = Cli::command().try_get_matches_from(custom).unwrap();
			assert_eq!(
				matches
					.subcommand_matches("limits")
					.unwrap()
					.get_one::<PathBuf>("config")
					.unwrap(),
				&PathBuf::from("/tmp/custom.toml"),
				"limits must accept config before or after the action"
			);
		}
	}
}

#[test]
fn limits_commands_reject_unknown_keys() {
	let error =
		Cli::command().try_get_matches_from(["epistle", "limits", "set", "unknown-limit", "12"]);
	assert_eq!(
		error.err().map(|error| error.kind()),
		Some(clap::error::ErrorKind::InvalidValue),
		"limits must reject unknown keys with the supported-key diagnostic"
	);
}

#[test]
fn limits_show_command_writes_data_without_restart() {
	let (_dir, file) = super::tests_config::config_file();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let calls = Cell::new(0);
	let code = run_with_restart(file.path(), Action::Show, &mut out, &mut status, |_, _| {
		calls.set(calls.get() + 1);
		ExitCode::SUCCESS
	});
	assert_eq!(
		code,
		ExitCode::SUCCESS,
		"limits show command must succeed on a valid config"
	);
	assert_eq!(
		String::from_utf8(out).unwrap().lines().next(),
		Some("quota\t5368709120 bytes\tdefault"),
		"limits show command must write the effective values to stdout"
	);
	assert!(
		status.is_empty(),
		"limits show must keep status output empty"
	);
	assert_eq!(calls.get(), 0, "limits show must not restart mail");
}

#[test]
fn limits_changes_without_compose_print_restart_and_skip_no_op() {
	let (_dir, file) = super::tests_config::config_file();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let calls = Cell::new(0);
	let mut run = |action| {
		status.clear();
		let code = run_with_restart(file.path(), action, &mut out, &mut status, |_, _| {
			calls.set(calls.get() + 1);
			ExitCode::SUCCESS
		});
		(code, String::from_utf8(status.clone()).unwrap())
	};
	assert_eq!(
		run(Action::Set {
			key: Key::Quota,
			value: "7G".into()
		}),
		(
			ExitCode::SUCCESS,
			"limits saved; server must be restarted\n".into()
		),
		"limits set must save and request a manual restart when compose is absent"
	);
	assert_eq!(
		Config::load(file.path()).unwrap().quota_bytes,
		Some(7 * 1024 * 1024 * 1024),
		"limits command must persist the configured quota"
	);
	assert_eq!(
		run(Action::Unset { key: Key::Quota }),
		(
			ExitCode::SUCCESS,
			"limits saved; server must be restarted\n".into()
		),
		"limits unset must save and request a manual restart"
	);
	assert_eq!(
		Config::load(file.path()).unwrap().quota_bytes,
		None,
		"limits unset command must remove the quota override"
	);
	let unchanged = std::fs::read(file.path()).unwrap();
	assert_eq!(
		run(Action::Unset { key: Key::Quota }),
		(ExitCode::SUCCESS, "limits unchanged\n".into()),
		"limits must report an unchanged config without restarting"
	);
	assert!(
		std::fs::read(file.path()).unwrap() == unchanged,
		"an unchanged limit must preserve original file bytes"
	);
	assert_eq!(
		calls.get(),
		0,
		"limits must not invoke stack restart when compose is absent"
	);
	assert!(
		out.is_empty(),
		"limits mutations must send status to stderr"
	);
}

#[test]
fn limits_with_compose_restart_only_mail_and_propagate_failure() {
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(compose, "services: {}\n").unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let calls = Cell::new(0);
	let code = run_with_restart(
		file.path(),
		Action::Set {
			key: Key::SubmissionRate,
			value: "120".into(),
		},
		&mut out,
		&mut status,
		|config, action| {
			calls.set(calls.get() + 1);
			assert_eq!(
				config.submission_rate_limit_per_min,
				Some(120),
				"mail restart must receive the updated config"
			);
			assert!(
				matches!(action, super::super::stack::StackAction::Restart { service: Some(service) } if service == "mail"),
				"limits must restart only the mail service through the stack action"
			);
			ExitCode::from(7)
		},
	);
	assert_eq!(
		code,
		ExitCode::from(7),
		"limits must propagate the stack restart exit code"
	);
	assert_eq!(
		calls.get(),
		1,
		"limits must restart mail after saving a changed config with compose"
	);
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"limits saved; restarting mail\n",
		"limits must report the persisted change before restarting mail"
	);
	assert_eq!(
		Config::load(file.path())
			.unwrap()
			.submission_rate_limit_per_min,
		Some(120),
		"a restart failure must retain the saved limit"
	);
}

#[test]
fn limits_invalid_command_value_preserves_bytes_and_reports_exact_error() {
	let (_dir, file) = super::tests_config::config_file();
	let original = std::fs::read(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let calls = Cell::new(0);
	let code = run_with_restart(
		file.path(),
		Action::Set {
			key: Key::Quota,
			value: "bogus".into(),
		},
		&mut out,
		&mut status,
		|_, _| {
			calls.set(calls.get() + 1);
			ExitCode::SUCCESS
		},
	);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"invalid limits values must exit with failure"
	);
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"cannot update limits: quota: expected a non-negative integer with a supported suffix within the field range\n",
		"invalid limits must print the exact key and value diagnostic"
	);
	assert!(
		std::fs::read(file.path()).unwrap() == original,
		"an invalid limits command must preserve original bytes"
	);
	assert_eq!(
		calls.get(),
		0,
		"an invalid limits command must not restart mail"
	);
}
