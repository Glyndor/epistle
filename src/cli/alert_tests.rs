use std::path::PathBuf;

use clap::{CommandFactory, Parser};

use super::*;
use crate::cli::resource::{Run, test_config};

pub(super) const ALERTS: &str = "
[webhook]
url = 'https://hooks.example/mail'

# bounce alarm
[[alerts]] # first
name = 'bounce-storm'
metric = 'bounced' # counter
op = '>='
threshold = 50
window_secs = 300
webhook = true
cooldown_secs = 900
";

pub(super) fn no_restart(_: &Config, _: StackAction) -> ExitCode {
	panic!("a test host has no compose file, so nothing may be restarted")
}

pub(super) fn run_with(extra: &str, args: &[&str], dry_run: bool) -> Run {
	let (_dir, file) = test_config(extra);
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut full = vec!["epistle", "alert"];
	full.extend_from_slice(args);
	let crate::cli::Command::Alert { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("alert arguments must select the alert command")
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		file.path(),
		action,
		dry_run,
		&mut out,
		&mut status,
		no_restart,
	);
	Run {
		result,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		after: std::fs::read_to_string(file.path()).unwrap(),
		before,
	}
}

pub(super) fn run(extra: &str, args: &[&str]) -> Run {
	run_with(extra, args, false)
}

#[test]
fn alert_accepts_config_before_or_after_the_action_and_defaults_it() {
	for (args, want) in [
		(vec!["epistle", "alert", "list"], "/etc/epistle/mail.toml"),
		(
			vec!["epistle", "alert", "--config", "/tmp/x.toml", "list"],
			"/tmp/x.toml",
		),
		(
			vec!["epistle", "alert", "list", "--config", "/tmp/x.toml"],
			"/tmp/x.toml",
		),
	] {
		let matches = crate::cli::Cli::command()
			.try_get_matches_from(args)
			.unwrap();
		assert_eq!(
			matches
				.subcommand_matches("alert")
				.unwrap()
				.get_one::<PathBuf>("config")
				.unwrap(),
			&PathBuf::from(want)
		);
	}
}

#[test]
fn operator_must_be_one_of_the_five_comparisons() {
	let rejected = crate::cli::Cli::command().try_get_matches_from([
		"epistle",
		"alert",
		"add",
		"x",
		"--metric",
		"bounced",
		"--op",
		"=>",
		"--threshold",
		"1",
		"--window",
		"1m",
		"--webhook",
	]);
	assert_eq!(
		rejected.err().map(|error| error.kind()),
		Some(clap::error::ErrorKind::InvalidValue)
	);
}

#[test]
fn list_prints_every_rule() {
	assert_eq!(
		run(ALERTS, &["list"]).out,
		"bounce-storm\tbounced >= 50\twindow=300s\tcooldown=900s\twebhook=yes\temail=-\n"
	);
	assert_eq!(
		super::tests::run(ALERTS, &["list", "--json"]).out,
		"[{\"name\":\"bounce-storm\",\"metric\":\"bounced\",\"op\":\">=\",\"threshold\":50,\"window_secs\":300,\"cooldown_secs\":900,\"webhook\":true,\"email\":[]}]\n"
	);
	assert_eq!(super::tests::run("", &["list"]).out, "");
	assert_eq!(super::tests::run("", &["list", "--json"]).out, "[]\n");
}

#[test]
fn remove_deletes_the_rule_and_keeps_its_comments() {
	let run = run(ALERTS, &["remove", "bounce-storm"]);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before.replace(
			"\n# bounce alarm\n[[alerts]] # first\nname = 'bounce-storm'\nmetric = 'bounced' # counter\nop = '>='\nthreshold = 50\nwindow_secs = 300\nwebhook = true\ncooldown_secs = 900\n",
			""
		) + "# bounce alarm\n# first\n# counter\n"
	);
	assert_eq!(run.status, "alert saved\nThe server must be restarted.\n");
}

#[test]
fn remove_reports_an_unknown_rule_and_dry_run_writes_nothing() {
	let run = run(ALERTS, &["remove", "nope"]);
	assert_eq!(run.result.unwrap_err(), "no alert named \"nope\"");
	assert!(run.after == run.before);
	let dry = run_with(ALERTS, &["remove", "bounce-storm"], true);
	assert!(dry.out.contains("-name = 'bounce-storm'"), "{}", dry.out);
	assert_eq!(dry.after, dry.before);
	assert!(dry.status.is_empty());
}
