//! `epistle warmup plan` and `epistle warmup start`.

use std::process::ExitCode;

use super::*;
use crate::cli::warmup::WarmupCli;
use crate::cli::{Cli, Command};
use crate::queue::warmup::Warmup;
use clap::Parser;

/// 01:00 UTC on 2025-10-14.
const NOW: u64 = 20_375 * 86_400 + 3600;

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

fn run_args(dir: &Path, args: &[&str]) -> (ExitCode, String) {
	let mut out = Vec::new();
	let code = crate::cli::warmup::run(dir, None, 30, parse(args).expect("parse"), NOW, &mut out);
	(code, String::from_utf8(out).expect("utf8"))
}

fn rows(group_line: impl Fn(&str) -> String) -> String {
	Group::ALL
		.iter()
		.map(|group| group_line(group.label()))
		.collect()
}

#[test]
fn ages_and_volumes_are_checked() {
	for (args, why) in [
		(&["plan", "--ip-age", "3x"][..], "not an age"),
		(&["plan", "--ip-age", "d"][..], "not an age"),
		(&["plan", "--ip-age=-1d"][..], "not an age"),
		(&["plan", "--ip-age", "101y"][..], "not an age"),
		(&["plan", "--ip-age", "3é"][..], "not an age"),
		(&["plan", "--daily-volume", "0"][..], "from 1 to 1000000"),
		(&["plan", "--group", "hotmail"][..], "unknown group"),
		(
			&["plan", "--group", "gmail", "--all"][..],
			"cannot be used with",
		),
	] {
		let error = parse(args).expect_err("refused");
		assert!(error.contains(why), "{args:?}: {error}");
	}
}

#[test]
fn a_new_address_sending_a_thousand_a_day_starts_at_fifty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (code, out) = run_args(
		dir.path(),
		&["plan", "--ip-age", "0d", "--daily-volume", "1000"],
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		out,
		format!(
			"plan: IP 0 days old, 1000 recipients a day (UTC day 2025-10-14)\n{}",
			rows(|group| format!("{group}\tstage=new\tcap=50\tnow=50\tdays=8\treach=2025-10-22\n"))
		)
	);
	assert!(
		!settings::path(dir.path()).exists(),
		"a plan writes nothing"
	);
}

#[test]
fn a_six_month_address_starts_at_its_volume_or_uncapped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (_, out) = run_args(
		dir.path(),
		&["plan", "--ip-age", "6m", "--daily-volume", "1000"],
	);
	assert_eq!(
		out,
		format!(
			"plan: IP 180 days old, 1000 recipients a day (UTC day 2025-10-14)\n{}",
			rows(|group| format!(
				"{group}\tstage=established\tcap=1000\tnow=50\tdays=0\treach=2025-10-14\n"
			))
		)
	);
	let (_, out) = run_args(
		dir.path(),
		&[
			"plan",
			"--ip-age",
			"6m",
			"--daily-volume",
			"6000",
			"--group",
			"gmail",
			"--json",
		],
	);
	assert_eq!(
		out,
		concat!(
			r#"{"daily_volume":6000,"day":"2025-10-14","groups":[{"applies":true,"cap":null,"#,
			r#""current":50,"days":0,"group":"gmail","reach":"2025-10-14","stage":"established"}],"#,
			r#""ip_age_days":180}"#,
			"\n"
		)
	);
}

#[test]
fn start_is_confirmed_and_reaches_the_running_server() {
	let dir = tempfile::tempdir().expect("tempdir");
	let server = Warmup::open(dir.path(), None, NOW);
	let args = ["start", "--ip-age", "3w", "--daily-volume", "1000"];
	assert_eq!(
		run_args(dir.path(), &args),
		(ExitCode::from(2), String::new())
	);
	assert!(
		!settings::path(dir.path()).exists(),
		"refused without --yes off a terminal"
	);

	let (code, out) = run_args(dir.path(), &[&args[..], &["--yes"]].concat());
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(out, rows(|group| format!("{group}: cap 250 (was 50)\n")));
	server.reload(NOW + 1).expect("reload");
	let (settings, state) = server.snapshot();
	assert!(settings.enabled);
	assert_eq!(
		Group::ALL.map(|group| state.group(group).cap),
		[Some(250); 5]
	);
	assert_eq!(
		state.group(Group::Gmail).raise,
		None,
		"a start is not on trial"
	);
}

#[test]
fn a_higher_or_lifted_cap_is_kept_unless_forced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut grown = State::new(20_375);
	grown.group_mut(Group::Gmail).cap = Some(863);
	grown.group_mut(Group::Other).cap = None;
	state::save(dir.path(), &grown).expect("state");

	let (_, out) = run_args(dir.path(), &["plan", "--group", "gmail"]);
	assert!(
		out.ends_with("gmail\tstage=new\tcap=50\tnow=863\tdays=12\treach=2025-10-26\tkept=863 (lower only with --force)\n"),
		"{out}"
	);
	let (code, out) = run_args(dir.path(), &["start", "--yes"]);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		out,
		concat!(
			"gmail: kept 863 (--force lowers it to 50)\n",
			"outlook: cap 50 (was 50)\n",
			"yahoo: cap 50 (was 50)\n",
			"icloud: cap 50 (was 50)\n",
			"other: kept none (--force lowers it to 50)\n",
		)
	);
	let server = Warmup::open(dir.path(), None, NOW);
	let state = server.snapshot().1;
	assert_eq!(
		(state.group(Group::Gmail).cap, state.group(Group::Other).cap),
		(Some(863), None)
	);

	let (_, out) = run_args(
		dir.path(),
		&["start", "--group", "gmail", "--force", "--yes"],
	);
	assert_eq!(out, "gmail: cap 50 (was 863)\n");
	server.reload(NOW + 1).expect("reload");
	assert_eq!(server.snapshot().1.group(Group::Gmail).cap, Some(50));
}
