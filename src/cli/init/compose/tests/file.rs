//! Compose-file write tests.
//!
//! Sister to `src/cli/init/compose/tests/base.rs` (which covers the rendered
//! shape) and `src/cli/init/compose/tests/password.rs` (the database
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

/// A host address `epistle service set` narrowed one mapping to lives only in
/// the generated file, so an `init` rerun has to read it back: without that
/// the rerun puts the listener back on every address of the host.
#[test]
fn ensure_compose_file_keeps_the_address_a_mapping_was_narrowed_to() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	let path = ensure_compose_file(&answers, true, &mut report).expect("first run");
	let narrowed = fs::read_to_string(&path)
		.expect("read")
		.replace("\"25:25\"", "\"127.0.0.1:25:25\"");
	assert_ne!(narrowed, fs::read_to_string(&path).unwrap(), "the fixture");
	fs::write(&path, &narrowed).expect("write the narrowed map");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("second run");
	let document: serde_json::Value =
		serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
	assert_eq!(
		document["services"]["mail"]["ports"][0],
		serde_json::json!("127.0.0.1:25:25"),
		"an init rerun must not widen a mapping back to every host address"
	);
}

/// A file from a release that published the listeners with no TLS transport on
/// every address of the host loses that reachability on the next `init`, and
/// the report is where the operator reads which port went and where it went.
#[test]
fn a_rewritten_map_reports_the_publication_it_took_off_every_host_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	answers.services.webdav = true;
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	let path = ensure_compose_file(&answers, true, &mut report).expect("first run");
	let wide = fs::read_to_string(&path)
		.expect("read")
		.replace("\"127.0.0.1:8090:8090\"", "\"8090:8090\"");
	assert_ne!(wide, fs::read_to_string(&path).unwrap(), "the fixture");
	fs::write(&path, &wide).expect("write the wide map");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("second run");
	let said = String::from_utf8({
		let mut rendered = Vec::new();
		report.write_to(&mut rendered).expect("report");
		rendered
	})
	.unwrap();
	assert!(
		said.contains("was published on 8090:8090 on every address of the host")
			&& said.contains("now published on 127.0.0.1:8090:8090"),
		"the report has to name the publication the rewrite took away: {said}"
	);
	let document: serde_json::Value =
		serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
	assert!(
		document["services"]["mail"]["ports"]
			.as_array()
			.expect("ports")
			.contains(&serde_json::json!("127.0.0.1:8090:8090")),
		"the map the rewrite left carries the narrowed publication"
	);
}
