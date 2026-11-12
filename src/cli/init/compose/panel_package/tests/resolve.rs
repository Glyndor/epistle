//! `resolve` decides whether the stack runs the panel from the override, the
//! pin file and the API. Nothing is rendered from it yet; the image it records
//! is what the service will be built from.

use super::*;
use crate::cli::init::compose::stack_answers;

const GOOD: &str = "ghcr.io/glyndor/epistle-panel:0.3.1";

struct Fixture {
	_dir: tempfile::TempDir,
	manifest: std::path::PathBuf,
}

/// A manifest holding `content`, or no file at all for `None`.
fn manifest(content: Option<&str>) -> Fixture {
	let dir = tempfile::tempdir().expect("tempdir");
	let manifest = dir.path().join("image");
	if let Some(content) = content {
		std::fs::write(&manifest, content).expect("write");
	}
	Fixture {
		_dir: dir,
		manifest,
	}
}

fn answers(panel: Option<bool>) -> Answers {
	let mut answers = stack_answers();
	answers.services.panel = panel;
	answers
}

#[test]
fn the_package_and_the_api_run_the_panel_without_any_answer() {
	let fixture = manifest(Some(&format!("{GOOD}\n")));
	let mut answers = answers(None);
	let notes = resolve(&mut answers, &fixture.manifest, true, true).expect("resolve");
	assert!(notes.is_empty(), "{notes:?}");
	assert_eq!(answers.services.panel_image.as_deref(), Some(GOOD));
}

#[test]
fn no_package_means_no_panel() {
	let fixture = manifest(None);
	let mut answers = answers(None);
	let notes = resolve(&mut answers, &fixture.manifest, true, true).expect("resolve");
	assert!(notes.is_empty(), "{notes:?}");
	assert_eq!(answers.services.panel_image, None);
}

#[test]
fn the_operator_can_decline_a_panel_the_package_would_add() {
	let fixture = manifest(Some(&format!("{GOOD}\n")));
	let mut answers = answers(Some(false));
	let notes = resolve(&mut answers, &fixture.manifest, true, true).expect("resolve");
	assert!(notes.is_empty(), "{notes:?}");
	assert_eq!(answers.services.panel_image, None);
}

#[test]
fn a_declined_panel_does_not_read_the_file() {
	let fixture = manifest(Some("not a reference\n"));
	let mut answers = answers(Some(false));
	assert_eq!(
		resolve(&mut answers, &fixture.manifest, true, true),
		Ok(Vec::new())
	);
}

#[test]
fn an_unusable_file_stops_init_and_names_it() {
	let fixture = manifest(Some("not a reference\n"));
	for panel in [None, Some(true)] {
		let mut answers = answers(panel);
		let error = resolve(&mut answers, &fixture.manifest, true, true).expect_err("unusable");
		assert!(
			error.starts_with(&format!("{} is not usable", fixture.manifest.display())),
			"{error}"
		);
		assert_eq!(answers.services.panel_image, None);
	}
}

#[test]
fn a_demanded_panel_without_the_package_fails_init_and_only_warns_an_update() {
	let fixture = manifest(None);
	let mut init = answers(Some(true));
	let error = resolve(&mut init, &fixture.manifest, true, true).expect_err("init");
	assert!(
		error.starts_with("services.panel is true, but the epistle-panel package is not installed"),
		"{error}"
	);
	assert!(
		error.contains(&fixture.manifest.display().to_string()),
		"{error}"
	);

	let mut update = answers(Some(true));
	let notes = resolve(&mut update, &fixture.manifest, true, false).expect("update");
	assert_eq!(notes.len(), 1, "{notes:?}");
	assert!(
		notes[0].starts_with("services.panel is true, but"),
		"{notes:?}"
	);
	assert_eq!(update.services.panel_image, None);
}

#[test]
fn without_the_api_the_panel_is_left_out_and_the_operator_is_told() {
	let fixture = manifest(Some(&format!("{GOOD}\n")));
	for panel in [None, Some(true)] {
		let mut answers = answers(panel);
		let notes = resolve(&mut answers, &fixture.manifest, false, true).expect("resolve");
		assert_eq!(notes.len(), 1, "{notes:?}");
		assert!(notes[0].contains("the management API is off"), "{notes:?}");
		assert_eq!(answers.services.panel_image, None);
	}
}

#[test]
fn an_image_from_an_earlier_resolution_does_not_survive_a_new_one() {
	let fixture = manifest(None);
	let mut answers = answers(None);
	answers.services.panel_image = Some(GOOD.to_string());
	resolve(&mut answers, &fixture.manifest, true, true).expect("resolve");
	assert_eq!(answers.services.panel_image, None);
}
