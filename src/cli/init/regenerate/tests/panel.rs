//! `stack update` rediscovers the panel choice from the compose file, and
//! reads the package's pin file when it decides whether the panel runs.

use super::{regenerate, regenerate_in};
use crate::cli::init::apply::listeners_to_write;
use crate::cli::init::compose::{render_for, stack_answers};

const GOOD: &str = "ghcr.io/glyndor/epistle-panel:0.3.1\n";

/// A stack whose answers set `panel` and the API.
fn answers(panel: Option<bool>, api: bool) -> crate::cli::init::Answers {
	let mut answers = stack_answers();
	answers.services.panel = panel;
	answers.services.api = api;
	answers
}

struct Case {
	_dir: tempfile::TempDir,
	manifest: std::path::PathBuf,
}

fn manifest(content: Option<&str>) -> Case {
	let dir = tempfile::tempdir().expect("tempdir");
	let manifest = dir.path().join("image");
	if let Some(content) = content {
		std::fs::write(&manifest, content).expect("write");
	}
	Case {
		_dir: dir,
		manifest,
	}
}

fn again(
	answers: &crate::cli::init::Answers,
	written: &str,
	case: &Case,
) -> Result<super::Regenerated, String> {
	let listeners = listeners_to_write(answers).expect("listeners");
	regenerate_in(&answers.data_dir, &listeners, written, None, &case.manifest)
}

fn key(text: &str) -> Option<serde_json::Value> {
	let value: serde_json::Value = serde_json::from_str(text).expect("json");
	value.get("x-epistle-panel").cloned()
}

#[test]
fn the_result_says_whether_the_stack_runs_the_panel() {
	let good = manifest(Some(GOOD));
	let none = manifest(None);
	for (panel, api, case, runs) in [
		(None, true, &good, true),
		(Some(true), true, &good, true),
		(None, true, &none, false),
		(Some(false), true, &good, false),
		(None, false, &good, false),
	] {
		let answers = answers(panel, api);
		let written = render_for(&answers, true).expect("render");
		let result = again(&answers, &written, case).expect("regenerate");
		assert_eq!(result.panel, runs, "panel {panel:?}, api {api}");
	}
}

#[test]
fn no_choice_writes_no_key_and_stays_byte_identical() {
	let answers = answers(None, true);
	let written = render_for(&answers, true).expect("render");
	assert_eq!(key(&written), None);
	for case in [manifest(None), manifest(Some(GOOD))] {
		assert_eq!(
			again(&answers, &written, &case).expect("regenerate").text,
			written
		);
	}
}

#[test]
fn a_declined_panel_is_written_and_survives_an_update() {
	let answers = answers(Some(false), true);
	let written = render_for(&answers, true).expect("render");
	assert_eq!(key(&written), Some(serde_json::json!(false)));
	let case = manifest(Some(GOOD));
	let result = again(&answers, &written, &case).expect("regenerate");
	assert_eq!(result.text, written);
	assert_eq!(key(&result.text), Some(serde_json::json!(false)));
}

#[test]
fn a_demanded_panel_is_written_and_survives_an_update() {
	let answers = answers(Some(true), true);
	let written = render_for(&answers, true).expect("render");
	assert_eq!(key(&written), Some(serde_json::json!(true)));
	let case = manifest(Some(GOOD));
	let result = again(&answers, &written, &case).expect("regenerate");
	assert_eq!(result.text, written);
	assert!(
		result.notes.iter().all(|note| !note.contains("panel")),
		"{:?}",
		result.notes
	);
}

#[test]
fn a_demanded_panel_whose_package_was_removed_updates_with_a_note() {
	let answers = answers(Some(true), true);
	let written = render_for(&answers, true).expect("render");
	let case = manifest(None);
	let result = again(&answers, &written, &case).expect("an update must not be refused");
	assert_eq!(result.text, written);
	assert!(
		result.notes.iter().any(|note| note
			.starts_with("services.panel is true, but the epistle-panel package is not installed")),
		"{:?}",
		result.notes
	);
}

#[test]
fn the_package_with_no_api_listener_is_a_note_not_a_change_to_the_api() {
	let answers = answers(None, false);
	let written = render_for(&answers, true).expect("render");
	let case = manifest(Some(GOOD));
	let result = again(&answers, &written, &case).expect("regenerate");
	assert_eq!(result.text, written);
	assert_eq!(
		result
			.notes
			.iter()
			.filter(|note| note.contains("the management API is off"))
			.count(),
		1,
		"{:?}",
		result.notes
	);
}

#[test]
fn the_package_with_an_api_listener_needs_no_note() {
	let answers = answers(None, true);
	let written = render_for(&answers, true).expect("render");
	let case = manifest(Some(GOOD));
	let result = again(&answers, &written, &case).expect("regenerate");
	assert!(
		result.notes.iter().all(|note| !note.contains("panel")),
		"{:?}",
		result.notes
	);
}

#[test]
fn an_unusable_pin_file_stops_the_update_and_names_the_file() {
	let answers = answers(None, true);
	let written = render_for(&answers, true).expect("render");
	let case = manifest(Some("ghcr.io/glyndor/epistle:0.3.1\n"));
	let error = again(&answers, &written, &case).expect_err("unusable");
	assert!(
		error.starts_with(&format!("{} is not usable", case.manifest.display())),
		"{error}"
	);
}

#[test]
fn a_declined_panel_ignores_an_unusable_pin_file() {
	let answers = answers(Some(false), true);
	let written = render_for(&answers, true).expect("render");
	let case = manifest(Some("garbage\n"));
	assert_eq!(
		again(&answers, &written, &case).expect("regenerate").text,
		written
	);
}

/// The update reads the fixed path, which is absent on a host without the
/// package, so the plain entry point keeps the key it finds.
#[test]
fn the_plain_entry_point_keeps_the_recorded_choice() {
	let answers = answers(Some(false), true);
	let written = render_for(&answers, true).expect("render");
	let listeners = listeners_to_write(&answers).expect("listeners");
	let result = regenerate(&answers.data_dir, &listeners, &written).expect("regenerate");
	assert_eq!(key(&result.text), Some(serde_json::json!(false)));
}
