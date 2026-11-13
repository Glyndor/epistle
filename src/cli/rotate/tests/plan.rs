//! What `epistle rotate --all --dry-run` prints and when it refuses.

use std::process::ExitCode;

use crate::cli::rotate::execute;
use crate::cli::rotate::registry::{entries, issue_url};

fn run(all: bool, dry_run: bool, json: bool) -> (ExitCode, String) {
	let mut out = Vec::new();
	let code = execute(all, dry_run, json, &mut out);
	(code, String::from_utf8(out).unwrap())
}

#[test]
fn the_text_plan_has_a_block_for_every_registry_row() {
	let (code, out) = run(true, true, false);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.starts_with("Dry run: nothing was changed."));
	for entry in entries() {
		assert!(
			out.contains(&format!("\n{}  ", entry.id)),
			"{} is missing",
			entry.id
		);
		assert!(out.contains(entry.stored_in));
	}
	assert!(out.contains(&issue_url(1497)));
}

#[test]
fn the_json_plan_lists_every_row_with_who_does_what() {
	let (code, out) = run(true, true, true);
	assert_eq!(code, ExitCode::SUCCESS);
	let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
	let rows = shown["entries"].as_array().unwrap();
	assert_eq!(rows.len(), entries().count());
	let storage = rows
		.iter()
		.find(|row| row["id"] == "storage-encryption-key")
		.unwrap();
	assert_eq!(storage["rotate"]["by"], "unsupported");
	assert_eq!(storage["rotate"]["issue_url"], issue_url(1497));
	let dkim = rows
		.iter()
		.find(|row| row["id"] == "dkim-signing-key")
		.unwrap();
	assert_eq!(dkim["rotate"]["by"], "epistle");
}

#[test]
fn without_dry_run_nothing_is_printed_and_nothing_runs() {
	let (code, out) = run(true, false, false);
	assert_eq!(code, ExitCode::from(3));
	assert!(out.is_empty());
}

#[test]
fn without_all_it_is_a_usage_error() {
	let (code, out) = run(false, true, false);
	assert_eq!(code, ExitCode::from(2));
	assert!(out.is_empty());
}
