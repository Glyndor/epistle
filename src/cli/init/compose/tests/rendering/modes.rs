//! The mode a secret or config mount carries, and the form it is written
//! in: the quoted octal string podup reads without a warning, and the
//! compose file an older release wrote, whose modes were numbers.
//!
//! podup 6.1.0 (measured 2026-11-26) warns about every mode written
//! without a leading 0 — `mode 400 is written without a leading 0 and was
//! read as octal digits: 0400 was applied` — for a number and for a string
//! alike, and asks for `0400`. The mode is therefore written as `"0400"`
//! and `"0444"`.

use std::fs;

use super::*;

/// The file an older release wrote: the same document with the modes as
/// the numbers they were.
fn with_numeric_modes(current: &str) -> String {
	let old = current
		.replace("\"mode\": \"0400\"", "\"mode\": 400")
		.replace("\"mode\": \"0444\"", "\"mode\": 444");
	assert_ne!(old, current, "the older file wrote the modes as numbers");
	old
}

#[test]
fn every_mode_is_written_as_a_quoted_octal_string() {
	let answers = stack_answers();
	let text = render_for(&answers, true).expect("render");
	assert!(
		text.contains("\"mode\": \"0400\""),
		"the secrets of the stack are mounted owner read-only: {text}"
	);
	assert!(
		text.contains("\"mode\": \"0444\""),
		"the roles script is mounted read-only for all: {text}"
	);
	// No mode is left as a number: podup reads a number digit by digit as
	// octal, and warns about every mode written without a leading 0.
	let value: serde_json::Value = serde_json::from_str(&text).expect("json");
	for (service, definition) in value["services"].as_object().expect("services") {
		for mount in definition["secrets"].as_array().into_iter().flatten() {
			assert!(mount["mode"].is_string(), "{service}: {mount}");
		}
		for mount in definition["configs"].as_array().into_iter().flatten() {
			assert!(mount["mode"].is_string(), "{service}: {mount}");
		}
	}
}

/// `stack update` reads the compose file on disk and renders it again. The
/// mode is not part of what it reads, so a file whose modes are numbers is
/// read like any other and comes back in the form podup reads without a
/// warning.
#[test]
fn a_compose_file_with_the_old_numeric_modes_still_reads() {
	let answers = stack_answers();
	let current = render_for(&answers, true).expect("render");
	let old = with_numeric_modes(&current);
	let again = crate::cli::init::regenerate(&answers.data_dir, &[], &old)
		.expect("a compose file with numeric modes still reads");
	assert!(
		again.text.contains("\"mode\": \"0400\"") && again.text.contains("\"mode\": \"0444\""),
		"the re-rendered file writes the modes the way podup reads them: {}",
		again.text
	);
}

/// The same for `init`: the apply phase reads the file that is there to
/// keep what the operator narrowed, and rewrites it with the modes the
/// current release writes.
#[test]
fn an_init_rerun_rewrites_a_file_whose_modes_were_numbers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	let path = ensure_compose_file(&answers, true, &mut report).expect("first run");
	let old = with_numeric_modes(&fs::read_to_string(&path).expect("read"));
	fs::write(&path, &old).expect("write the old file");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("second run");
	let rewritten = fs::read_to_string(&path).expect("read");
	assert!(
		rewritten.contains("\"mode\": \"0400\"") && rewritten.contains("\"mode\": \"0444\""),
		"the file is brought to the modes podup reads without a warning: {rewritten}"
	);
}
