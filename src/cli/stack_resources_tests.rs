//! Tests for `epistle stack resources` on the compose file `init` renders.

use std::process::ExitCode;

use serde_json::{Value, json};

use super::{ResourcesCli, run, set_limits};

const GIB: u64 = 1024 * 1024 * 1024;

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
	assert_eq!(run(&compose, None, true, &mut out), ExitCode::SUCCESS);
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
	assert_eq!(run(&compose, None, false, &mut out), ExitCode::SUCCESS);
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
	let code = run(&compose, set("clamav", Some("2g"), None), true, &mut out);
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
	] {
		assert_eq!(
			set_limits(&text, service, memory, pids).map(|_| ()),
			Err(refusal.to_string()),
			"{service} {memory:?} {pids:?}"
		);
		let mut out = Vec::new();
		let code = run(&compose, set(service, memory, pids), false, &mut out);
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
