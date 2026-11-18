//! The admin id: one per installation, generated once, kept, never rewritten.

use super::super::admin_id::is_admin_id;
use super::*;

/// A valid id to put in place by hand.
const MINE: &str = "3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f";

/// Create the secrets directory and return the admin id path.
fn id_path(layout: &Layout) -> PathBuf {
	let path = admin_id_path(&layout.data);
	std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
	path
}

fn assert_nothing_written(layout: &Layout) {
	assert!(
		!api_token_path(&layout.data).exists() && !session_secret_path(&layout.data).exists(),
		"a refusal of the admin id must leave the other files unwritten"
	);
	assert_eq!(count_keys(layout), 0, "no key row on a refusal");
}

#[test]
fn the_first_run_writes_a_canonical_lower_case_uuid_v4_with_no_line_ending() {
	let layout = layout();
	run(&layout, NOW);
	let id = text(&admin_id_path(&layout.data));
	assert!(is_admin_id(&id), "{id:?} is not a lower-case UUID v4");
	assert_eq!(id.len(), 36, "no line ending in the id");
}

#[test]
fn the_file_is_owner_only() {
	let layout = layout();
	run(&layout, NOW);
	assert_eq!(mode(&admin_id_path(&layout.data)), 0o600);
}

#[test]
fn two_installations_get_two_different_ids() {
	let ids: std::collections::HashSet<String> = (0..16)
		.map(|_| {
			let layout = layout();
			run(&layout, NOW);
			text(&admin_id_path(&layout.data))
		})
		.collect();
	assert_eq!(ids.len(), 16, "an id repeated: {ids:?}");
}

#[test]
fn the_report_of_a_first_run_names_the_file_as_written() {
	let layout = layout();
	let report = run(&layout, NOW);
	assert!(
		kinds(&report).contains(&("wrote", admin_id_path(&layout.data))),
		"{:?}",
		kinds(&report)
	);
}

#[test]
fn a_later_run_keeps_the_id_byte_for_byte_however_much_time_passes() {
	let layout = layout();
	run(&layout, NOW);
	let path = admin_id_path(&layout.data);
	let before = text(&path);
	for day in [1, 40, 340, 400] {
		let report = run(&layout, NOW + day * DAY);
		assert!(kinds(&report).contains(&("reused", path.clone())));
		assert_eq!(text(&path), before, "the id changed on day {day}");
	}
}

#[test]
fn an_id_the_operator_put_there_is_kept_and_is_the_one_shown() {
	let layout = layout();
	let path = id_path(&layout);
	std::fs::write(&path, format!("{MINE}\n")).expect("write");
	run(&layout, NOW);
	assert_eq!(
		text(&path),
		format!("{MINE}\n"),
		"the file is left as it is"
	);
	assert_eq!(
		read_admin_id(&layout.data).expect("read").as_deref(),
		Some(MINE)
	);
}

#[test]
fn a_wider_mode_is_narrowed_and_the_content_is_kept() {
	use std::os::unix::fs::PermissionsExt;
	let layout = layout();
	let path = id_path(&layout);
	std::fs::write(&path, MINE).expect("write");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
	run(&layout, NOW);
	assert_eq!(mode(&path), 0o600);
	assert_eq!(text(&path), MINE);
}

#[test]
fn the_plan_says_generate_then_reuse() {
	let layout = layout();
	assert_eq!(
		decide(&layout.data, NOW).expect("decide").admin_id,
		AdminIdAction::Generate
	);
	run(&layout, NOW);
	assert_eq!(
		decide(&layout.data, NOW).expect("decide").admin_id,
		AdminIdAction::Reuse
	);
	assert!(
		!kinds(&run(&layout, NOW)).is_empty(),
		"deciding wrote nothing it should not have"
	);
}

#[test]
fn anything_that_is_not_an_id_is_refused_naming_the_path_and_never_the_content() {
	let wrong = [
		"mail",
		"3F2B8C1E-5D4A-4B7E-9C3D-1A2B3C4D5E6F",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"018f3a6e-7b2c-7c5a-9a3b-1c2d3e4f5a6b",
		"3f2b8c1e-5d4a-4b7e-cc3d-1a2b3c4d5e6f",
		" 3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f",
		"3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f0",
		"3f2b8c1e5d4a4b7e9c3d1a2b3c4d5e6f",
		"3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6g",
		// A line break inside, or a second line: one id and nothing else.
		"3f2b8c1e-5d4a-4b7e-9c3d\n-1a2b3c4d5e6f",
		"3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f\nextra",
		"\n3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f",
		"3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f\n\nextra\n",
		"3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f\0",
	];
	for content in wrong {
		let layout = layout();
		let path = id_path(&layout);
		std::fs::write(&path, content).expect("write");
		let message = refusal(&layout, NOW);
		assert!(message.contains(&path.display().to_string()), "{message}");
		assert!(
			!message.contains(content.trim()) || content.trim().is_empty(),
			"{message}"
		);
		assert_eq!(text(&path), content, "{content:?} was overwritten");
		assert_nothing_written(&layout);
		assert!(
			read_admin_id(&layout.data).is_err(),
			"{content:?} was shown"
		);
	}
}

#[test]
fn a_symlink_in_place_of_the_id_is_refused_and_left_alone() {
	let layout = layout();
	let path = id_path(&layout);
	let target = layout.data.join("elsewhere");
	std::fs::write(&target, MINE).expect("write");
	std::os::unix::fs::symlink(&target, &path).expect("symlink");
	let message = refusal(&layout, NOW);
	assert!(message.contains("path is a symlink"), "{message}");
	assert_eq!(text(&target), MINE);
	assert!(
		std::fs::symlink_metadata(&path)
			.expect("meta")
			.file_type()
			.is_symlink()
	);
	assert_nothing_written(&layout);
	assert!(read_admin_id(&layout.data).is_err());
}

#[test]
fn a_directory_or_an_empty_file_in_place_of_the_id_is_refused() {
	let layout = layout();
	std::fs::create_dir_all(admin_id_path(&layout.data)).expect("dir");
	assert!(refusal(&layout, NOW).contains("path is not a regular file"));
	let layout = self::layout();
	std::fs::write(id_path(&layout), "").expect("write");
	assert!(refusal(&layout, NOW).contains("file is empty"));
	assert_nothing_written(&layout);
}

#[test]
fn nothing_shows_an_id_that_is_not_there() {
	let layout = layout();
	assert_eq!(read_admin_id(&layout.data).expect("read"), None);
}

#[test]
fn the_shape_rule_is_the_panels() {
	assert!(is_admin_id(MINE));
	assert!(is_admin_id("00000000-0000-4000-8000-000000000000"));
	assert!(is_admin_id("ffffffff-ffff-4fff-bfff-ffffffffffff"));
	assert!(!is_admin_id("00000000-0000-1000-8000-000000000000"));
	assert!(!is_admin_id("00000000-0000-4000-7000-000000000000"));
	assert!(!is_admin_id("00000000-0000-4000-c000-000000000000"));
	assert!(!is_admin_id("0000000-00000-4000-8000-000000000000"));
	assert!(!is_admin_id(""));
}
