use std::os::unix::fs::{PermissionsExt, symlink};

use crate::storage::create_private_dir;

fn mode(path: &std::path::Path) -> u32 {
	std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[test]
fn creates_nested_dirs_owner_only() {
	let root = tempfile::tempdir().expect("tempdir");
	let leaf = root.path().join("a").join("b").join("c");
	create_private_dir(root.path(), &leaf).expect("create");
	assert_eq!(mode(&leaf), 0o700);
	assert_eq!(mode(&root.path().join("a")), 0o700);
	assert_eq!(mode(&root.path().join("a").join("b")), 0o700);
}

#[test]
fn tightens_an_existing_loose_dir() {
	let root = tempfile::tempdir().expect("tempdir");
	let dir = root.path().join("loose");
	std::fs::create_dir(&dir).expect("mkdir");
	std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	create_private_dir(root.path(), &dir).expect("create");
	assert_eq!(mode(&dir), 0o700);
}

#[test]
fn refuses_a_path_that_escapes_through_dot_dot() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("root");
	std::fs::create_dir(&root).expect("mkdir");
	let escaped = root.join("..").join("outside");
	let error = create_private_dir(&root, &escaped).expect_err("must refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert!(!outer.path().join("outside").exists());
}

#[test]
fn refuses_a_symlink_pointing_outside_the_root() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("root");
	let target = outer.path().join("target");
	std::fs::create_dir(&root).expect("mkdir root");
	std::fs::create_dir(&target).expect("mkdir target");
	symlink(&target, root.join("link")).expect("symlink");
	let error = create_private_dir(&root, &root.join("link").join("child")).expect_err("refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert!(!target.join("child").exists());
}

#[test]
fn refuses_a_dangling_link_inside_the_root() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("root");
	std::fs::create_dir(&root).expect("mkdir root");
	symlink(outer.path().join("missing"), root.join("link")).expect("symlink");
	let error = create_private_dir(&root, &root.join("link")).expect_err("refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert!(!outer.path().join("missing").exists());
}
