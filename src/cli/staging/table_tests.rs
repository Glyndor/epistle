use super::*;
use crate::cli::command_cases::CASES;
use clap::Parser;

/// Top-level commands that re-execute as the service account, from the
/// table every command must have a delegation decision in.
fn delegated() -> std::collections::BTreeSet<&'static str> {
	CASES
		.iter()
		.filter(|(_, delegates)| *delegates)
		.map(|(args, _)| args[0])
		.collect()
}

fn names_a_path(arg: &clap::Arg) -> bool {
	let typed = arg.get_value_parser().type_id() == std::any::TypeId::of::<PathBuf>();
	let named = arg.get_value_names().is_some_and(|names| {
		names
			.iter()
			.any(|name| ["FILE", "DIR", "PATH"].contains(&name.as_str()))
	});
	typed || named
}

fn walk(command: &clap::Command, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
	for arg in command.get_arguments().filter(|arg| names_a_path(arg)) {
		out.push((path.clone(), arg.get_id().to_string()));
	}
	for sub in command.get_subcommands() {
		path.push(sub.get_name().to_owned());
		walk(sub, path, out);
		path.pop();
	}
}

#[test]
fn every_path_argument_of_a_delegated_command_is_staged_or_exempt() {
	let delegated = delegated();
	let mut found = Vec::new();
	for top in crate::cli::Cli::command().get_subcommands() {
		if delegated.contains(top.get_name()) {
			walk(top, &mut vec![top.get_name().to_owned()], &mut found);
		}
	}
	assert!(
		found
			.iter()
			.any(|(path, arg)| path == &["import"] && arg == "maildir"),
		"the walk must reach nested arguments: {found:?}"
	);
	for (path, arg) in &found {
		let staged = STAGED
			.iter()
			.any(|entry| entry.command == path.as_slice() && entry.arg == arg);
		let exempt = NOT_STAGED.iter().any(|(command, id, _)| {
			id == arg && command.is_none_or(|command| command == path.as_slice())
		});
		assert!(
			staged || exempt,
			"`epistle {} --{arg}` names a path on a command that runs as the service \
			 account: add it to STAGED in staging/table.rs, or to NOT_STAGED with the \
			 reason the account can use it where it is",
			path.join(" ")
		);
		assert!(
			!(staged && exempt),
			"{path:?} {arg} is both staged and exempt"
		);
	}
	for entry in STAGED {
		assert!(
			found
				.iter()
				.any(|(path, arg)| path == entry.command && arg == entry.arg),
			"STAGED lists {:?} {} that no delegated command has",
			entry.command,
			entry.arg
		);
	}
}

fn args(list: &[&str]) -> Vec<OsString> {
	list.iter().map(OsString::from).collect()
}

#[test]
fn finds_both_spellings_and_stops_at_the_terminator() {
	let line = args(&[
		"migrate",
		"imap",
		"--account",
		"alice",
		"--host",
		"imap.example.org",
		"--user",
		"alice",
		"--password-file",
		"/tmp/pw",
		"--ca-file=/tmp/ca.pem",
	]);
	let found = find(&line, STAGED);
	assert_eq!(
		found,
		[
			Found {
				token: 9,
				prefix: None,
				value: "/tmp/pw".into(),
				kind: STAGED[0].kind,
			},
			Found {
				token: 10,
				prefix: Some("--ca-file=".into()),
				value: "/tmp/ca.pem".into(),
				kind: STAGED[1].kind,
			},
		]
	);
	let mut after = args(&["import", "--account", "alice", "--", "--maildir", "/x"]);
	assert!(
		find(&after, STAGED).is_empty(),
		"nothing after `--` is a flag"
	);
	after.truncate(3);
	assert!(find(&after, STAGED).is_empty());
}

#[test]
fn only_the_subcommand_that_runs_is_searched() {
	// `--maildir` belongs to both import and export: the kind follows the
	// command that is running.
	let import = find(
		&args(&["import", "--account", "a", "--maildir", "/m"]),
		STAGED,
	);
	let export = find(
		&args(&["export", "--account", "a", "--maildir", "/m"]),
		STAGED,
	);
	assert!(matches!(import[0].kind, Kind::ReadDir { .. }));
	assert_eq!(export[0].kind, Kind::WriteDir);
	assert!(find(&args(&["queue", "list"]), STAGED).is_empty());
	assert!(
		find(&args(&["status", "--config", "/tmp/mail.toml"]), STAGED).is_empty(),
		"--config is never staged"
	);
}

#[test]
fn a_command_line_missing_a_required_argument_is_still_searched() {
	// The account picker re-executes before the line parses: the path is
	// staged all the same.
	let line = args(&["migrate", "imap", "--password-file", "/tmp/pw"]);
	assert!(
		crate::cli::Cli::try_parse_from(
			std::iter::once(OsString::from("epistle")).chain(line.iter().cloned())
		)
		.is_err()
	);
	let found = find(&line, STAGED);
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].value, PathBuf::from("/tmp/pw"));
}
