use clap::Parser;

use super::super::LogsArgs;

#[derive(Parser)]
struct Wrapper {
	#[command(flatten)]
	args: LogsArgs,
}

fn parse(words: &[&str]) -> Result<LogsArgs, clap::Error> {
	Wrapper::try_parse_from(std::iter::once("logs").chain(words.iter().copied()))
		.map(|wrapper| wrapper.args)
}

#[test]
fn the_default_is_the_last_two_hundred_lines() {
	assert_eq!(parse(&[]).unwrap().range_argv(), ["-n", "200"]);
}

#[test]
fn tail_all_since_and_until_reach_podup() {
	assert_eq!(parse(&["--tail", "20"]).unwrap().range_argv(), ["-n", "20"]);
	assert_eq!(parse(&["--all"]).unwrap().range_argv(), ["-n", "all"]);
	assert_eq!(
		parse(&["--since", "10m", "--until", "2026-11-15T08:00:00"])
			.unwrap()
			.range_argv(),
		[
			"-n",
			"200",
			"--since",
			"10m",
			"--until",
			"2026-11-15T08:00:00"
		]
	);
}

#[test]
fn services_are_merged_by_default_only_when_there_is_more_than_one() {
	let plain = parse(&[]).unwrap();
	assert!(!plain.merges(1));
	assert!(plain.merges(2));
	assert!(parse(&["--merge"]).unwrap().merges(1));
	assert!(!parse(&["--no-merge"]).unwrap().merges(5));
}

#[test]
fn contradicting_flags_are_refused() {
	assert!(parse(&["--tail", "5", "--all"]).is_err());
	assert!(parse(&["--merge", "--no-merge"]).is_err());
	assert!(parse(&["--follow", "--no-merge"]).is_err());
	assert!(parse(&["--tail", "-1"]).is_err());
}
