//! `--dry-run` leave-no-trace scenario. The `--answers` TOML is
//! well-formed and the plan is non-empty, so without `--dry-run`
//! the apply phase would create the data dir, write every key, and
//! render the config. With `--dry-run` the run must surface the
//! plan on stderr and exit 0 without touching the filesystem.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::helpers::{binary, make_answers_body, write_answers};

#[test]
fn dry_run_writes_nothing_to_a_fresh_tempdir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&make_answers_body(&data_dir, &config_path),
	);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap(), "--dry-run"]);
	cmd.stdin(Stdio::null());
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(output.status.success(), "dry-run exit: {:?}", output.status);
	assert!(
		output.stdout.is_empty(),
		"dry-run wrote to stdout: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);
	let mut entries: Vec<PathBuf> = std::fs::read_dir(dir.path())
		.expect("read_dir")
		.map(|entry| entry.expect("entry").path())
		.collect();
	entries.retain(|path| path != &answers);
	entries.sort();
	assert_eq!(
		entries,
		Vec::<PathBuf>::new(),
		"dry-run must leave only the answers file behind; entries: {entries:?}"
	);
}
