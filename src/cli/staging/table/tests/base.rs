use super::*;
use crate::cli::command::tests::cases::CASES;
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

const MESSAGE: Kind = Kind::ReadFile {
	limit: MESSAGE_LIMIT,
	secret: false,
};

fn message_found(token: usize, value: &str) -> Found {
	Found {
		token,
		prefix: None,
		value: value.into(),
		kind: MESSAGE,
	}
}

#[test]
fn a_positional_path_is_found_by_its_place_on_the_line() {
	assert_eq!(
		find(
			&args(&["attachments", "check", "/tmp/m.eml", "--json"]),
			STAGED
		),
		[message_found(2, "/tmp/m.eml")]
	);
	assert_eq!(
		find(
			&args(&["attachments", "check", "--json", "/tmp/m.eml"]),
			STAGED
		),
		[message_found(3, "/tmp/m.eml")]
	);
}

#[test]
fn a_positional_path_after_the_terminator_is_still_a_path() {
	// A file called `--json` can only be named after `--`.
	assert_eq!(
		find(&args(&["attachments", "check", "--", "--json"]), STAGED),
		[message_found(3, "--json")]
	);
	// And a file called like the subcommand is the last token, not the command.
	assert_eq!(
		find(&args(&["attachments", "check", "check"]), STAGED),
		[message_found(2, "check")]
	);
}

#[test]
fn only_check_stages_a_path_in_attachments() {
	assert!(find(&args(&["attachments", "policy", "show"]), STAGED).is_empty());
	assert!(find(&args(&["attachments", "check"]), STAGED).is_empty());
}

#[test]
fn a_positional_path_is_found_by_its_place_not_by_its_value() {
	// The same text is also the value of another flag: the file is the
	// token clap read as the positional.
	assert_eq!(
		find(
			&args(&["attachments", "check", "foo", "--config", "foo"]),
			STAGED
		),
		[message_found(2, "foo")]
	);
	assert_eq!(
		find(
			&args(&["attachments", "check", "--config", "foo", "foo"]),
			STAGED
		),
		[message_found(4, "foo")]
	);
	assert_eq!(
		find(
			&args(&["attachments", "--config", "m.eml", "check", "m.eml"]),
			STAGED
		),
		[message_found(4, "m.eml")]
	);
}

#[test]
fn a_line_repeating_the_path_many_times_is_searched_with_a_bound() {
	// A synthetic command whose option can repeat, so that 5000 tokens
	// read `foo` as an option value before the positional `foo`.
	let root = clap::Command::new("epistle").subcommand(
		clap::Command::new("c")
			.arg(
				clap::Arg::new("opt")
					.long("opt")
					.action(clap::ArgAction::Append),
			)
			.arg(clap::Arg::new("file")),
	);
	let mut line = args(&["c"]);
	for _ in 0..5_000 {
		line.extend(args(&["--opt", "foo"]));
	}
	line.push("foo".into());
	let argv = std::iter::once(OsString::from("epistle")).chain(line.iter().cloned());
	let matches = root.clone().try_get_matches_from(argv).unwrap();
	let entry = Staged {
		command: &["c"],
		arg: "file",
		kind: MESSAGE,
	};
	let mut found = Vec::new();
	let started = std::time::Instant::now();
	positional(
		&line,
		&root,
		matches.subcommand_matches("c").unwrap(),
		&entry,
		&mut found,
	);
	assert!(
		started.elapsed() < std::time::Duration::from_secs(5),
		"the number of probes is bounded"
	);
	assert!(found.is_empty(), "past the bound nothing is staged");
}

#[test]
fn the_message_staged_for_check_is_bounded_by_the_default_message_size() {
	// docs/cli.md tells the operator a larger `max_message_size` needs the
	// service account; the copy for root stops at the default.
	let entry = STAGED
		.iter()
		.find(|entry| entry.command == ["attachments", "check"])
		.expect("check stages its file");
	assert_eq!(
		entry.kind,
		Kind::ReadFile {
			limit: crate::smtp::session::MAX_MESSAGE_SIZE as u64,
			secret: false,
		}
	);
}

#[test]
fn the_path_of_check_is_found_among_the_global_flags() {
	assert_eq!(
		find(
			&args(&[
				"attachments",
				"--config",
				"/etc/mail.toml",
				"check",
				"/tmp/m.eml",
				"--strict",
				"--json"
			]),
			STAGED
		),
		[message_found(4, "/tmp/m.eml")]
	);
}

#[test]
fn the_file_of_a_suppression_import_is_staged_as_a_read() {
	let found = find(
		&args(&[
			"suppression",
			"import",
			"--account",
			"bob",
			"/root/list.csv",
			"--dry-run",
		]),
		STAGED,
	);
	assert_eq!(found.len(), 1, "{found:?}");
	assert_eq!(found[0].value, std::path::PathBuf::from("/root/list.csv"));
	assert_eq!(
		found[0].kind,
		Kind::ReadFile {
			limit: FILE_LIMIT,
			secret: false
		}
	);
}
