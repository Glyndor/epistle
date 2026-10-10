//! Compose-file write tests.
//!
//! Sister to `compose_tests.rs` (which covers the rendered
//! shape) and `compose_password_tests.rs` (the database
//! secret). The tests here drive `ensure_compose_file` end to
//! end: the first run writes the file, the second run says
//! `identical, not touched`, and a different answer set forces
//! a rewrite. The README next to `compose.yaml` is asserted to
//! mention both `podup` and `init` so an operator landing on
//! the file knows what to do with it.

use std::fs;

use super::{ensure_compose_file, stack_answers};

#[test]
fn ensure_compose_file_writes_then_says_identical() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	let path = ensure_compose_file(&answers, true, &mut report).expect("first run");
	assert!(path.exists(), "compose file must be written");
	let mut report2 = crate::cli::init::apply::Report::default();
	let _ = ensure_compose_file(&answers, true, &mut report2).expect("second run");
	let step = report2
		.steps
		.iter()
		.find(|s| matches!(s, crate::cli::init::apply::ReportStep::ConfigIdentical(_)))
		.expect("second run must say identical");
	match step {
		crate::cli::init::apply::ReportStep::ConfigIdentical(p) => {
			assert!(p.ends_with("compose.yaml"));
		}
		_ => unreachable!(),
	}
}

#[test]
fn ensure_compose_file_writes_a_readme_next_to_compose() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("write compose");
	let readme = data_dir.join("compose").join("README");
	assert!(
		readme.exists(),
		"README must be written next to compose.yaml"
	);
	let body = fs::read_to_string(&readme).expect("read README");
	assert!(body.contains("podup"), "README must mention podup");
	assert!(body.contains("init"), "README must mention init");
}

#[test]
fn ensure_compose_file_refuses_to_overwrite_with_different_answers() {
	// A second run with different services must rewrite the file
	// (the operator can confirm with the same plan step).
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("first run");
	// Enable webdav and run again; the published ports now include
	// 8090:8090, so the desired bytes change.
	answers.services.webdav = true;
	let mut report2 = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report2).expect("second run");
	let step = report2
		.steps
		.iter()
		.find(|s| matches!(s, crate::cli::init::apply::ReportStep::Wrote(_)))
		.expect("second run must report a Wrote step");
	if let crate::cli::init::apply::ReportStep::Wrote(p) = step {
		assert!(p.ends_with("compose.yaml"));
	} else {
		unreachable!()
	}
}
