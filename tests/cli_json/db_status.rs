//! `db status`: one read-only query run in the stack's database container.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde_json::json;

use crate::harness::{Env, env, epistle_in, json};

const DATABASE: &str =
	"[database]\nurl = \"postgres://epistle@localhost/epistle\"\ntls = \"insecure\"\n";

/// A `podup` that records its arguments in `calls.txt`, then prints
/// `row.txt` and exits with `exit.txt`, as `podup exec ... psql` would.
fn stub(env: &Env, row: &str, exit: i32, stderr: &str) -> PathBuf {
	let bin = env.dir.path().join("bin");
	std::fs::create_dir_all(&bin).expect("bin dir");
	std::fs::write(bin.join("row.txt"), row).expect("row");
	std::fs::write(bin.join("exit.txt"), exit.to_string()).expect("exit");
	std::fs::write(bin.join("stderr.txt"), stderr).expect("stderr");
	let shim = bin.join("podup");
	std::fs::write(
		&shim,
		"#!/bin/sh\nd=\"$(dirname \"$0\")\"\n\
		 if [ \"$1\" = \"--version\" ]; then echo 'podup version v5.10.13'; exit 0; fi\n\
		 printf '%s\\n' \"$*\" >> \"$d/calls.txt\"\n\
		 cat \"$d/row.txt\"\ncat \"$d/stderr.txt\" >&2\nexit \"$(cat \"$d/exit.txt\")\"\n",
	)
	.expect("shim");
	std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	let compose = env.data_dir().join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("compose dir");
	std::fs::write(&compose, b"# compose fixture\n").expect("compose");
	bin
}

fn run(env: &Env, bin: &PathBuf, json_flag: bool) -> std::process::Output {
	let mut args = vec!["db", "--config", &env.config, "status"];
	if json_flag {
		args.push("--json");
	}
	epistle_in(&args, b"", Some(bin))
}

#[test]
fn status_reports_the_database_as_one_object() {
	let env = env(DATABASE);
	let bin = stub(&env, "16.4|8192000|12|3|100\n", 0, "");
	let output = run(&env, &bin, true);
	let (code, value) = json(&output);
	assert_eq!(code, 0);
	assert_eq!(
		value,
		json!({
			"database": "epistle", "version": "16.4", "size_bytes": 8_192_000,
			"tables": 12, "connections": 3, "max_connections": 100,
		})
	);
}

#[test]
fn status_in_text_is_one_fact_per_line() {
	let env = env(DATABASE);
	let bin = stub(&env, "16.4|8192000|12|3|100\n", 0, "");
	let output = run(&env, &bin, false);
	assert_eq!(output.status.code(), Some(0));
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"database\tepistle\nversion\t16.4\nsize_bytes\t8192000\ntables\t12\nconnections\t3 of 100\n"
	);
}

#[test]
fn status_only_reads() {
	let env = env(DATABASE);
	let bin = stub(&env, "16.4|1|1|1|100\n", 0, "");
	assert_eq!(run(&env, &bin, true).status.code(), Some(0));
	let calls = std::fs::read_to_string(bin.join("calls.txt")).expect("calls");
	assert_eq!(calls.lines().count(), 1, "one podup call: {calls}");
	let lower = calls.to_ascii_lowercase();
	assert!(lower.contains("select "), "{calls}");
	for word in [
		"insert", "update ", "delete", "drop", "alter", "create ", "truncate", "vacuum", "grant",
		"copy ", "set ",
	] {
		assert!(
			!lower.contains(word),
			"the status query must not contain {word:?}: {calls}"
		);
	}
}

#[test]
fn a_failed_query_leaves_stdout_empty() {
	let env = env(DATABASE);
	let bin = stub(
		&env,
		"",
		2,
		"psql: FATAL: the database system is starting up\n",
	);
	let output = run(&env, &bin, true);
	assert_eq!(output.status.code(), Some(1));
	assert!(output.stdout.is_empty());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("the database system is starting up"),
		"{stderr}"
	);
}

#[test]
fn an_answer_that_is_not_five_numbers_and_a_version_is_refused() {
	let env = env(DATABASE);
	for row in [
		"",
		"garbage\n",
		"16.4|big|12|3|100\n",
		"16.4|1|2|3\n",
		"16.4|1|2|3|4|5\n",
		"16.4|-1|2|3|4\n",
	] {
		let bin = stub(&env, row, 0, "");
		let output = run(&env, &bin, true);
		assert_eq!(output.status.code(), Some(1), "{row:?}");
		assert!(output.stdout.is_empty(), "{row:?}");
		assert!(
			String::from_utf8_lossy(&output.stderr).contains("unexpected answer"),
			"{row:?}: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
}

#[test]
fn the_version_is_escaped_before_it_is_printed() {
	let env = env(DATABASE);
	let bin = stub(&env, "16.4\u{1b}[2J|1|1|1|100\n", 0, "");
	let output = run(&env, &bin, false);
	assert_eq!(output.status.code(), Some(0));
	let stdout = String::from_utf8_lossy(&output.stdout);
	assert!(!stdout.contains('\u{1b}'), "{stdout:?}");
	assert!(stdout.contains("16.4\\u{1b}[2J"), "{stdout:?}");
}

#[test]
fn without_a_database_or_a_stack_there_is_nothing_to_ask() {
	let bare = env("");
	let bin = stub(&bare, "16.4|1|1|1|100\n", 0, "");
	let output = run(&bare, &bin, true);
	assert_eq!(output.status.code(), Some(3));
	assert!(output.stdout.is_empty());
	assert_eq!(
		String::from_utf8_lossy(&output.stderr).trim_end(),
		"error: the config has no [database]; the stack runs without PostgreSQL"
	);
	let no_stack = env(DATABASE);
	let output = epistle_in(
		&["db", "--config", &no_stack.config, "status", "--json"],
		b"",
		Some(&no_stack.dir.path().join("none")),
	);
	assert_eq!(output.status.code(), Some(3));
	assert!(output.stdout.is_empty());
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("there is no stack"),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
}
