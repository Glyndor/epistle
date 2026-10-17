//! The `--json` result of `restore` names the archive's entries from the
//! archive itself, so a member name cannot add or hide a path.

use std::process::ExitCode;

use serde_json::json;

use super::restore_json;
use crate::cli::backup;
use crate::config::Config;

fn config_for(data_dir: &std::path::Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {data_dir:?}\n"
	))
	.expect("config")
}

/// A name that, printed as a line of text, reads as a second entry.
const HOSTILE: &str = "zz\n  data/FAKE_ENTRY_INJECTED";

#[test]
fn a_member_name_with_a_line_break_stays_one_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = backup::tar_gz(&[
		("first".into(), 0o600, b"first".to_vec()),
		(HOSTILE.into(), 0o600, b"second".to_vec()),
	])
	.expect("archive");
	let mut printed = Vec::new();
	let mut status = Vec::new();
	let (exit, summary) = backup::run_restore_reporting(
		&config_for(&data_dir),
		&archive,
		true,
		true,
		&mut printed,
		&mut status,
	);
	assert_eq!(exit, ExitCode::SUCCESS);
	let result = restore_json(&summary, true);
	assert_eq!(result["entries"], 2);
	let paths = result["paths"].as_array().expect("paths");
	assert_eq!(paths.len(), 2, "paths: {paths:?}");
	assert_eq!(
		result,
		json!({
			"result": "dry-run", "action": "restore", "entries": 2,
			"paths": ["data/first", format!("data/{HOSTILE}")],
		})
	);
	// The text form shows the name with its line break escaped, so it
	// cannot pass for a second line of the listing.
	let text = String::from_utf8(printed).expect("utf8");
	assert!(
		!text
			.lines()
			.any(|line| line.contains("FAKE_ENTRY_INJECTED") && line.starts_with("  data/FAKE")),
		"the name forged a listing line: {text}"
	);
	assert!(
		text.contains("\\n"),
		"the line break was not escaped: {text}"
	);
}

#[test]
fn a_real_restore_counts_the_entries_it_laid_down() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = backup::tar_gz(&[
		("data/first".into(), 0o600, b"one".to_vec()),
		("data/second".into(), 0o600, b"two".to_vec()),
		("data/third".into(), 0o600, b"three".to_vec()),
	])
	.expect("archive");
	let mut printed = Vec::new();
	let mut status = Vec::new();
	let (exit, summary) = backup::run_restore_reporting(
		&config_for(&data_dir),
		&archive,
		true,
		false,
		&mut printed,
		&mut status,
	);
	assert_eq!(exit, ExitCode::SUCCESS);
	assert_eq!(
		restore_json(&summary, false),
		json!({"result": "saved", "action": "restore", "entries": 3})
	);
	assert_eq!(
		std::fs::read(data_dir.join("second")).expect("restored file"),
		b"two"
	);
}
