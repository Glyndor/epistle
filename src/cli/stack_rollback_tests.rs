//! Tests for choosing what `stack rollback` restores.

use std::collections::BTreeSet;

use super::{confirm, migrations_in_dump, pick, question, restored, schema_moved, summary};

fn files(names: &[&str]) -> Vec<String> {
	names.iter().map(|name| name.to_string()).collect()
}

#[test]
fn the_newest_version_below_the_running_one_is_picked() {
	let kept = files(&[
		"epistle-0.10.1",
		"epistle-0.9.2",
		"epistle-0.11.0",
		"notes.txt",
	]);
	assert_eq!(
		pick(&kept, "0.11.0", None),
		Ok("epistle-0.10.1".to_string())
	);
	assert_eq!(
		pick(&kept, "0.12.0", None),
		Ok("epistle-0.11.0".to_string())
	);
	assert_eq!(
		pick(&kept, "0.10.10", None),
		Ok("epistle-0.10.1".to_string()),
		"numeric, not text order"
	);
}

#[test]
fn an_explicit_version_must_be_kept() {
	let kept = files(&["epistle-0.10.1", "epistle-0.9.2"]);
	assert_eq!(
		pick(&kept, "0.11.0", Some("0.9.2")),
		Ok("epistle-0.9.2".to_string())
	);
	let error = pick(&kept, "0.11.0", Some("0.8.0")).unwrap_err();
	assert!(
		error.contains("0.8.0") && error.contains("0.10.1"),
		"{error}"
	);
}

#[test]
fn nothing_kept_is_an_error_that_says_why() {
	let error = pick(&[], "0.11.0", None).unwrap_err();
	assert!(error.contains("no earlier binary"), "{error}");
	let error = pick(&files(&["epistle-0.11.0"]), "0.11.0", None).unwrap_err();
	assert!(error.contains("no earlier binary"), "{error}");
}

const DUMP: &str = "SET statement_timeout = 0;\n\
COPY public.accounts (id, name) FROM stdin;\n\
1\talice\n\
\\.\n\
COPY public._sqlx_migrations (version, description, installed_on, success, checksum, execution_time) FROM stdin;\n\
20250101000000\tinit\t2026-01-01 00:00:00+00\tt\t\\\\x00\t1\n\
20260901000000\tqueue\t2026-09-01 00:00:00+00\tt\t\\\\x00\t1\n\
\\.\n\
COPY public.domains (id) FROM stdin;\n\
20990101000000\n\
\\.\n";

#[test]
fn the_dump_migrations_are_read_from_their_copy_block_only() {
	assert_eq!(
		migrations_in_dump(DUMP),
		BTreeSet::from([20250101000000, 20260901000000])
	);
	assert!(migrations_in_dump("").is_empty());
}

#[test]
fn a_migration_the_dump_lacks_means_the_schema_moved() {
	let dump = migrations_in_dump(DUMP);
	assert!(!schema_moved(&dump, &dump));
	let mut newer = dump.clone();
	newer.insert(20261012000000);
	assert!(schema_moved(&dump, &newer));
}

/// Run [`confirm`] on a console over `typed`; the result and stderr.
fn ask(interactive: bool, typed: &str, yes: bool) -> (Result<(), std::process::ExitCode>, String) {
	let mut input = std::io::Cursor::new(typed.as_bytes().to_vec());
	let mut err = Vec::new();
	let result = confirm(
		&mut crate::cli::prompt::Console {
			interactive,
			tty: None,
			input: &mut input,
			err: &mut err,
		},
		"0.11.0",
		"0.10.1",
		yes,
	);
	(result, String::from_utf8(err).unwrap())
}

#[test]
fn the_question_names_both_versions_and_what_may_be_restored() {
	let text = question("0.11.0", "0.10.1");
	assert!(
		text.contains("0.11.0") && text.contains("0.10.1") && text.contains("/usr/bin/epistle"),
		"{text}"
	);
	assert!(text.contains("database"), "{text}");
}

#[test]
fn rollback_follows_the_destructive_command_convention() {
	let (result, err) = ask(false, "", false);
	assert_eq!(
		result,
		Err(std::process::ExitCode::from(2)),
		"no terminal, no --yes"
	);
	assert!(err.contains("--yes"), "{err}");
	let (result, err) = ask(false, "", true);
	assert_eq!(result, Ok(()), "--yes skips the question");
	assert!(err.is_empty(), "{err}");
	let (result, err) = ask(true, "n\n", false);
	assert_eq!(result, Err(std::process::ExitCode::from(2)), "answered no");
	assert!(err.contains("0.10.1") && err.contains("cancelled"), "{err}");
	assert_eq!(ask(true, "yes\n", false).0, Ok(()));
}

#[test]
fn yes_parses_long_and_short() {
	use clap::Parser;
	for argv in [
		&["epistle", "stack", "rollback", "--yes"][..],
		&["epistle", "stack", "rollback", "-y", "--to", "0.10.1"][..],
	] {
		let cli = crate::cli::Cli::try_parse_from(argv).expect("parses");
		assert!(
			matches!(
				cli.command,
				crate::cli::Command::Stack {
					action: crate::cli::stack::StackCli::Rollback { yes: true, .. },
					..
				}
			),
			"{argv:?}"
		);
	}
}

#[test]
fn lost_database_changes_are_named_only_when_the_dump_was_restored() {
	assert!(restored("database=restored\n"));
	assert!(!restored("database=kept\n") && !restored(""));
	let back = summary("0.11.0", "0.10.1", true);
	assert!(back.contains("gone from the database"), "{back}");
	let kept = summary("0.11.0", "0.10.1", false);
	assert!(!kept.contains("gone"), "{kept}");
	assert!(kept.contains("database was kept"), "{kept}");
	for text in [back, kept] {
		assert!(
			text.contains("apt-mark hold epistle") && text.contains("0.10.1"),
			"{text}"
		);
	}
}
