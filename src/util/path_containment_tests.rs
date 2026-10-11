use super::*;

use std::fs;

fn data_dir() -> (tempfile::TempDir, PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("data");
	fs::create_dir_all(root.join("accounts/alice")).expect("create tree");
	let root = root.canonicalize().expect("canonical root");
	(dir, root)
}

#[test]
fn nested_path_under_the_root_is_accepted() {
	let (_guard, root) = data_dir();
	let existing = contained(&root, &root.join("accounts/alice")).expect("existing dir");
	assert_eq!(existing, root.join("accounts/alice"));
	let missing = contained(&root, &root.join("accounts/alice/folders/Work/new"))
		.expect("a directory that does not exist yet");
	assert_eq!(missing, root.join("accounts/alice/folders/Work/new"));
}

#[test]
fn dot_dot_that_leaves_the_root_is_refused() {
	let (_guard, root) = data_dir();
	let outside = root.join("accounts/alice/../../../outside");
	let error = contained(&root, &outside).expect_err("must not leave the root");
	assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn dot_dot_that_stays_inside_the_root_resolves_to_the_real_location() {
	let (_guard, root) = data_dir();
	let resolved = contained(&root, &root.join("accounts/alice/../alice")).expect("inside");
	assert_eq!(resolved, root.join("accounts/alice"));
}

#[test]
fn dot_dot_in_the_part_that_does_not_exist_is_refused() {
	let (_guard, root) = data_dir();
	for candidate in ["accounts/missing/../alice", "accounts/alice/a..b/new"] {
		let error = contained(&root, &root.join(candidate)).expect_err(candidate);
		assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{candidate}");
	}
}

#[test]
fn absolute_path_outside_the_root_is_refused() {
	let (guard, root) = data_dir();
	let sibling = guard.path().join("elsewhere");
	fs::create_dir_all(&sibling).expect("sibling");
	let error = contained(&root, &sibling).expect_err("sibling of the root");
	assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
	let prefix_twin = guard.path().join("data-twin");
	fs::create_dir_all(&prefix_twin).expect("twin");
	let error = contained(&root, &prefix_twin).expect_err("shares a name prefix only");
	assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[cfg(unix)]
#[test]
fn symlink_pointing_outside_the_root_is_refused() {
	let (guard, root) = data_dir();
	let outside = guard.path().join("outside");
	fs::create_dir_all(&outside).expect("outside");
	std::os::unix::fs::symlink(&outside, root.join("accounts/link")).expect("symlink");
	let error = contained(&root, &root.join("accounts/link/new")).expect_err("through the link");
	assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn root_that_does_not_exist_yet_still_contains_its_children() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("canonical").join("fresh");
	let child = contained(&root, &root.join("accounts/alice")).expect("inside a new root");
	assert_eq!(child, root.join("accounts/alice"));
}
