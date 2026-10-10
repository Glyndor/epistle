use super::*;
use std::os::unix::fs::symlink;

#[test]
fn config_symlink_swapped_after_preflight_is_refused_before_read() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let path = dir.path().join("mail.toml");
	std::fs::write(&path, "hostname = \"mail.example.org\"\n").expect("write config");
	let mut answers = crate::cli::init::compose::minimal_answers();
	answers.config_path = path.clone();
	answers.data_dir = dir.path().join("data");
	// Custom image mode skips the host-binary check the test
	// environment cannot satisfy (no `/usr/bin/epistle`).
	answers.image = Some("localhost/epistle:dev".to_string());
	assert!(
		super::super::plan(&answers).is_ok(),
		"regular config must pass preflight"
	);
	let target = dir.path().join("private.toml");
	std::fs::write(&target, "[dns]\ntoken = \"opaque\" trailing-garbage\n").expect("write target");
	std::fs::remove_file(&path).expect("remove config");
	symlink(target.canonicalize().expect("absolute target"), &path).expect("swap symlink");
	assert!(
		matches!(existing_operators_listeners(&path), Err(ApplyError::ConfigSymlink(ref rejected)) if rejected == &path),
		"config swapped to a symlink must be rejected before reading its target"
	);
	assert!(
		matches!(merge_with_existing(&path, "hostname = \"mail.example.org\"", false), Err(ApplyError::ConfigSymlink(ref rejected)) if rejected == &path),
		"config merge must reject a symlink before reading its target"
	);
}
