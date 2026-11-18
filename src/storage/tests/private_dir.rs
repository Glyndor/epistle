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

#[test]
fn a_planted_leaf_link_outside_the_root_is_refused_and_its_target_untouched() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("root");
	let target = outer.path().join("target");
	std::fs::create_dir(&root).expect("mkdir root");
	std::fs::create_dir(&target).expect("mkdir target");
	std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	symlink(&target, root.join("leaf")).expect("symlink");
	let error = create_private_dir(&root, &root.join("leaf")).expect_err("refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(mode(&target), 0o755);
}

#[test]
fn two_threads_creating_the_same_dir_both_succeed() {
	for round in 0..20 {
		let root = tempfile::tempdir().expect("tempdir");
		let leaf = root.path().join(format!("day{round}")).join("x");
		let barrier = std::sync::Barrier::new(2);
		std::thread::scope(|scope| {
			let work = || {
				barrier.wait();
				create_private_dir(root.path(), &leaf)
			};
			let first = scope.spawn(work);
			let second = scope.spawn(work);
			first.join().expect("join").expect("first");
			second.join().expect("join").expect("second");
		});
		assert_eq!(mode(&leaf), 0o700);
	}
}

#[test]
fn a_missing_root_is_created_owner_only() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("not").join("yet");
	create_private_dir(&root, &root.join("child")).expect("create");
	assert_eq!(mode(&root), 0o700);
	assert_eq!(mode(&root.join("child")), 0o700);
}

#[test]
fn a_name_with_dots_inside_is_an_ordinary_name() {
	let root = tempfile::tempdir().expect("tempdir");
	let dir = root.path().join("a..b");
	create_private_dir(root.path(), &dir).expect("create");
	assert_eq!(mode(&dir), 0o700);
}

#[test]
fn a_non_utf8_name_is_an_ordinary_name() {
	use std::os::unix::ffi::OsStrExt;
	let root = tempfile::tempdir().expect("tempdir");
	let dir = root.path().join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
	create_private_dir(root.path(), &dir).expect("create");
	assert_eq!(mode(&dir), 0o700);
}

#[test]
fn a_regular_file_at_the_leaf_is_already_exists() {
	let root = tempfile::tempdir().expect("tempdir");
	let file = root.path().join("file");
	std::fs::write(&file, b"x").expect("write");
	let error = create_private_dir(root.path(), &file).expect_err("refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn a_path_outside_the_root_is_refused() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("root");
	std::fs::create_dir(&root).expect("mkdir");
	let error = create_private_dir(&root, &outer.path().join("sibling")).expect_err("refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert!(!outer.path().join("sibling").exists());
}

#[test]
fn a_root_that_is_a_link_is_followed() {
	let outer = tempfile::tempdir().expect("tempdir");
	let real = outer.path().join("real");
	std::fs::create_dir(&real).expect("mkdir");
	let root = outer.path().join("root");
	symlink(&real, &root).expect("symlink");
	create_private_dir(&root, &root.join("child")).expect("create");
	assert_eq!(mode(&real.join("child")), 0o700);
}

#[test]
fn a_leaf_link_resolving_inside_the_root_is_allowed() {
	let root = tempfile::tempdir().expect("tempdir");
	let real = root.path().join("real");
	std::fs::create_dir(&real).expect("mkdir");
	symlink(&real, root.path().join("alias")).expect("symlink");
	create_private_dir(root.path(), &root.path().join("alias")).expect("create");
	assert_eq!(mode(&real), 0o700);
}

#[test]
fn a_preexisting_parent_is_left_as_it_was_and_the_leaf_is_tightened() {
	let root = tempfile::tempdir().expect("tempdir");
	let parent = root.path().join("parent");
	std::fs::create_dir(&parent).expect("mkdir");
	std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	create_private_dir(root.path(), &parent.join("leaf")).expect("create");
	assert_eq!(mode(&parent), 0o755);
	assert_eq!(mode(&parent.join("leaf")), 0o700);
}

#[test]
fn a_missing_root_is_created_owner_only_one_name_at_a_time() {
	let outer = tempfile::tempdir().expect("tempdir");
	let root = outer.path().join("x").join("y").join("root");
	let leaf = root.join("leaf");
	create_private_dir(&root, &leaf).expect("create");
	assert_eq!(mode(&leaf), 0o700);
	assert_eq!(mode(&root), 0o700);
	assert_eq!(mode(&outer.path().join("x").join("y")), 0o700);
}

#[test]
fn a_root_behind_a_dangling_link_is_refused() {
	let outer = tempfile::tempdir().expect("tempdir");
	let link = outer.path().join("link");
	symlink(outer.path().join("missing"), &link).expect("symlink");
	let root = link.join("root");
	let error = create_private_dir(&root, &root.join("leaf")).expect_err("refuse");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert!(!outer.path().join("missing").exists());
}
