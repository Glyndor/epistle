//! Tests for `epistle stack resources` on the compose file `init` renders.

use std::process::ExitCode;

use serde_json::{Value, json};

use super::{ResourcesCli, mail_floor_problem, run, set_limits};

const GIB: u64 = 1024 * 1024 * 1024;

/// The default `max_message_size`, 25 MiB.
const LARGEST: u64 = 25 * 1024 * 1024;

/// A data dir with the compose file `init` writes for a stack with a
/// database, and the path of that file.
fn stack() -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	std::fs::write(
		&compose,
		crate::cli::init::rendered_for_tests(dir.path(), None),
	)
	.expect("compose");
	(dir, compose)
}

fn set(service: &str, memory: Option<&str>, pids: Option<u32>) -> Option<ResourcesCli> {
	Some(ResourcesCli::Set {
		service: service.to_string(),
		memory: memory.map(str::to_string),
		pids,
	})
}

fn document(path: &std::path::Path) -> Value {
	serde_json::from_slice(&std::fs::read(path).expect("read")).expect("json")
}

#[test]
fn resources_lists_each_service_limit_as_json() {
	let (_dir, compose) = stack();
	let mut out = Vec::new();
	assert_eq!(
		run(&compose, LARGEST, None, true, &mut out),
		ExitCode::SUCCESS
	);
	let printed: Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(
		printed,
		json!({
			"services": [
				{"service": "clamav", "memory": "3g", "memory_bytes": 3 * GIB, "pids": 128},
				{"service": "db", "memory": "1g", "memory_bytes": GIB, "pids": 256},
				{"service": "freshclam", "memory": "2g", "memory_bytes": 2 * GIB, "pids": 32},
				{"service": "mail", "memory": "1g", "memory_bytes": GIB, "pids": 1024},
			],
			"total_bytes": 7 * GIB,
		})
	);
}

#[test]
fn resources_prints_a_table_with_the_total() {
	let (_dir, compose) = stack();
	let mut out = Vec::new();
	assert_eq!(
		run(&compose, LARGEST, None, false, &mut out),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(out).expect("utf8"),
		"SERVICE    MEMORY  PIDS\n\
		 clamav     3g      128\n\
		 db         1g      256\n\
		 freshclam  2g      32\n\
		 mail       1g      1024\n\
		 total      7g\n"
	);
}

#[test]
fn set_records_the_limit_where_stack_update_reads_it_back() {
	let (dir, compose) = stack();
	let mut out = Vec::new();
	let code = run(
		&compose,
		LARGEST,
		set("clamav", Some("2g"), None),
		true,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let printed: Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(
		printed,
		json!({
			"before": {"service": "clamav", "memory": "3g", "memory_bytes": 3 * GIB, "pids": 128},
			"after": {"service": "clamav", "memory": "2g", "memory_bytes": 2 * GIB, "pids": 128},
		})
	);
	let written = document(&compose);
	assert_eq!(
		written["x-epistle-resources"]["clamav"],
		json!({"memory": "2g"})
	);
	assert_eq!(written["services"]["clamav"]["mem_limit"], "2g");
	assert_eq!(written["services"]["clamav"]["pids_limit"], 128);
	assert_eq!(written["services"]["freshclam"]["mem_limit"], "2g");
	assert_eq!(written["services"]["mail"]["mem_limit"], "1g");
	let text = std::fs::read_to_string(&compose).expect("read");
	let again = crate::cli::init::regenerate(dir.path(), &[], &text).expect("regenerate");
	let rendered: Value = serde_json::from_str(&again.text).expect("json");
	assert_eq!(
		rendered["services"]["clamav"]["mem_limit"], "2g",
		"stack update renders the recorded value"
	);
}

#[test]
fn set_prints_what_changed_and_how_to_apply_it() {
	let (_dir, compose) = stack();
	let mut out = Vec::new();
	let code = run(
		&compose,
		LARGEST,
		set("mail", Some("2g"), Some(2048)),
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		String::from_utf8(out).expect("utf8"),
		format!(
			"mail: memory 1g -> 2g, pids 1024 -> 2048\n\
			 written to {}; `epistle stack update` recreates mail with it\n",
			compose.display()
		)
	);
}

#[test]
fn set_refuses_what_init_refuses_and_writes_nothing() {
	let (_dir, compose) = stack();
	let text = std::fs::read_to_string(&compose).expect("read");
	for (service, memory, pids, refusal) in [
		(
			"clamav",
			Some("2gb"),
			None,
			"resources.clamav.memory \"2gb\" is not a whole number above 0 followed by k, m or g",
		),
		(
			"clamav",
			None,
			Some(0),
			"resources.clamav.pids must be at least 1",
		),
		(
			"web",
			Some("1g"),
			None,
			"resources.web is not a service of the stack; use one of mail, db, clamav, freshclam",
		),
		("clamav", None, None, "give --memory, --pids or both"),
		(
			"clamav",
			Some("99999999999g"),
			None,
			"resources.clamav.memory \"99999999999g\" is more than 64-bit sizes reach",
		),
		(
			"db",
			Some("6143k"),
			None,
			"resources.db.memory \"6143k\" is under the 6m Podman accepts",
		),
	] {
		assert_eq!(
			set_limits(&text, service, memory, pids).map(|_| ()),
			Err(refusal.to_string()),
			"{service} {memory:?} {pids:?}"
		);
		let mut out = Vec::new();
		let code = run(
			&compose,
			LARGEST,
			set(service, memory, pids),
			false,
			&mut out,
		);
		assert_eq!(code, ExitCode::FAILURE);
		assert_eq!(std::fs::read_to_string(&compose).expect("read"), text);
	}
}

#[test]
fn set_refuses_a_service_the_stack_does_not_run() {
	let (_dir, compose) = stack();
	let mut without_db = document(&compose);
	without_db["services"]
		.as_object_mut()
		.expect("services")
		.remove("db");
	let text = serde_json::to_string_pretty(&without_db).expect("json");
	assert_eq!(
		set_limits(&text, "db", Some("2g"), None).map(|_| ()),
		Err("compose.yaml has no `db` service".to_string())
	);
}

#[test]
fn the_command_line_reads_set_and_json_on_either_side() {
	use clap::Parser;
	let parsed = crate::cli::Cli::try_parse_from([
		"epistle",
		"stack",
		"resources",
		"set",
		"clamav",
		"--memory",
		"2g",
		"--json",
	])
	.expect("parses");
	let crate::cli::Command::Stack { action, .. } = parsed.command else {
		panic!("not a stack command");
	};
	let crate::cli::stack::StackCli::Resources { json, action } = action else {
		panic!("not stack resources");
	};
	assert!(json);
	assert!(matches!(
		action,
		Some(ResourcesCli::Set { ref service, ref memory, pids: None })
			if service == "clamav" && memory.as_deref() == Some("2g")
	));
}

#[test]
fn a_compose_file_over_one_mib_is_refused_unread() {
	let (_dir, compose) = stack();
	let mut text = std::fs::read_to_string(&compose).expect("read");
	text.push_str(&" ".repeat(2 * 1024 * 1024));
	std::fs::write(&compose, &text).expect("pad");
	let mut out = Vec::new();
	assert_eq!(
		run(&compose, LARGEST, None, true, &mut out),
		ExitCode::FAILURE
	);
	assert!(out.is_empty(), "nothing listed");
	let code = run(
		&compose,
		LARGEST,
		set("clamav", Some("2g"), None),
		true,
		&mut out,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert_eq!(
		std::fs::read_to_string(&compose).expect("read").len(),
		text.len(),
		"the file is left as it was"
	);
}

#[test]
fn control_characters_in_the_compose_file_do_not_reach_the_terminal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	std::fs::write(
		&compose,
		r#"{"services":{"mail\u001b[2J":{"mem_limit":"1g\u001b]0;x\u0007","pids_limit":5}}}"#,
	)
	.expect("compose");
	let mut out = Vec::new();
	assert_eq!(
		run(&compose, LARGEST, None, false, &mut out),
		ExitCode::SUCCESS
	);
	let printed = String::from_utf8(out).expect("utf8");
	assert!(
		!printed.chars().any(|c| c == '\u{1b}' || c == '\u{7}'),
		"escape bytes were printed: {:?}",
		printed.escape_debug().to_string()
	);
}

#[test]
fn set_refuses_a_mail_limit_under_what_the_largest_message_needs() {
	let (_dir, compose) = stack();
	let before = std::fs::read(&compose).expect("read");
	let mut out = Vec::new();
	let code = run(
		&compose,
		LARGEST,
		set("mail", Some("256m"), None),
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert_eq!(
		std::fs::read(&compose).expect("read"),
		before,
		"nothing written"
	);
	// 300 MiB messages need five of them and 256 MiB: 1756 MiB.
	let code = run(
		&compose,
		300 << 20,
		set("mail", Some("1755m"), None),
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::FAILURE);
	let code = run(
		&compose,
		300 << 20,
		set("mail", Some("1756m"), None),
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(document(&compose)["services"]["mail"]["mem_limit"], "1756m");
}

#[test]
fn the_mail_floor_names_the_least_it_takes() {
	assert_eq!(
		mail_floor_problem("mail", Some("256m"), LARGEST),
		Some(
			"mail needs at least 381m for messages of up to 25 MiB: 5 of them and 256 MiB \
			 for the server itself; give it more, or lower max_message_size first"
				.to_string()
		)
	);
	assert_eq!(mail_floor_problem("mail", Some("381m"), LARGEST), None);
	assert_eq!(mail_floor_problem("mail", None, LARGEST), None, "pids only");
	assert_eq!(
		mail_floor_problem("clamav", Some("256m"), LARGEST),
		None,
		"only mail holds messages"
	);
	assert_eq!(
		mail_floor_problem("mail", Some("1g"), 1_000_000),
		None,
		"a size in bytes, not whole MiB"
	);
	assert_eq!(
		mail_floor_problem("mail", Some("260m"), 1_000_000)
			.map(|problem| problem.starts_with("mail needs at least 261m ")),
		Some(true),
		"rounded up to the next MiB"
	);
}
