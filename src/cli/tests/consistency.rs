//! Rules every resource follows, checked over the whole command tree so a
//! new action cannot skip them: `list` and `show` take `--json`, and each
//! command's short help fits an 80-column terminal.

use clap::CommandFactory;

use crate::cli::Cli;

/// Every visible subcommand, with its path from the root.
fn visible_commands() -> Vec<(String, clap::Command)> {
	fn walk(prefix: &str, command: &clap::Command, out: &mut Vec<(String, clap::Command)>) {
		for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
			let path = format!("{prefix} {}", sub.get_name());
			out.push((path.clone(), sub.clone()));
			walk(&path, sub, out);
		}
	}
	let mut root = Cli::command();
	root.build();
	let mut out = Vec::new();
	walk("epistle", &root, &mut out);
	out
}

#[test]
fn every_list_and_show_takes_json() {
	let missing: Vec<String> = visible_commands()
		.into_iter()
		.filter(|(_, command)| matches!(command.get_name(), "list" | "show"))
		.filter(|(_, command)| !command.get_arguments().any(|arg| arg.get_id() == "json"))
		.map(|(path, _)| path)
		.collect();
	assert!(missing.is_empty(), "no --json on: {missing:#?}");
}

#[test]
fn every_about_is_one_short_line() {
	let long: Vec<String> = visible_commands()
		.into_iter()
		.filter_map(|(path, command)| {
			let about = command
				.get_about()
				.map(ToString::to_string)
				.unwrap_or_default();
			(about.is_empty() || about.contains('\n') || about.chars().count() >= 80)
				.then(|| format!("{path}: {about:?}"))
		})
		.collect();
	assert!(long.is_empty(), "about lines to shorten: {long:#?}");
}

#[test]
fn epistle_help_fits_eighty_columns() {
	let help = Cli::command().render_help().to_string();
	let wide: Vec<&str> = help
		.lines()
		.filter(|line| line.chars().count() > 80)
		.collect();
	assert!(
		wide.is_empty(),
		"`epistle --help` lines over 80 columns: {wide:#?}"
	);
}
