//! The walk and the change act on what each entry was when it was opened:
//! a directory or file whose name is replaced by a link during the walk is
//! refused or left alone, and nothing outside the tree is touched.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use super::{IdShift, Shift, apply, walk};

/// The caller's own uid kept as it is, so the real change is allowed
/// without privilege while still counting as a move.
fn unchanged() -> Shift {
	// SAFETY: getuid takes no arguments and cannot fail.
	let uid = unsafe { libc::getuid() };
	Shift {
		uid: Some(IdShift {
			from: uid,
			to: uid,
			count: 1,
		}),
		gid: None,
	}
}

fn outside_file(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let file = dir.path().join("secret");
	std::fs::write(&file, "x").unwrap();
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
	(dir, file)
}

fn replace_with_link(path: &Path, target: &Path, kept: &str) {
	let moved = path.with_file_name(kept);
	std::fs::rename(path, &moved).unwrap();
	std::os::unix::fs::symlink(target, path).unwrap();
}

#[test]
fn a_directory_replaced_by_a_link_stops_the_walk() {
	let (outside, secret) = outside_file(0o600);
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	std::fs::create_dir(root.join("a")).unwrap();
	std::fs::write(root.join("a/file"), "x").unwrap();
	let guarded = std::fs::metadata(&secret).unwrap().ino();
	let mut visited = Vec::new();
	let result = walk(root, unchanged(), &mut |visit, _, _| {
		visited.push(visit.meta.ino());
		if visit.path == root.join("a") {
			replace_with_link(&root.join("a"), outside.path(), "a.moved");
		}
		Ok(())
	});
	let error = result.expect_err("the replaced directory must stop the walk");
	assert!(
		error.to_string().contains("symbolic link"),
		"the error says why: {error}"
	);
	assert!(!visited.contains(&guarded), "nothing outside was visited");
	assert_eq!(std::fs::metadata(&secret).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn a_link_in_the_tree_is_visited_as_the_link() {
	let (outside, secret) = outside_file(0o4755);
	let dir = tempfile::tempdir().unwrap();
	std::os::unix::fs::symlink(&secret, dir.path().join("link")).unwrap();
	std::os::unix::fs::symlink(outside.path(), dir.path().join("dir-link")).unwrap();
	let guarded = std::fs::metadata(&secret).unwrap().ino();
	let mut links = 0;
	walk(dir.path(), unchanged(), &mut |visit, _, _| {
		assert_ne!(visit.meta.ino(), guarded);
		links += u32::from(visit.meta.file_type().is_symlink());
		Ok(())
	})
	.unwrap();
	assert_eq!(links, 2, "both links are entries, neither is followed");
}

#[test]
fn the_change_goes_to_the_opened_file_even_when_its_name_is_swapped() {
	let (outside, secret) = outside_file(0o600);
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	let file = root.join("file");
	std::fs::write(&file, "x").unwrap();
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4755)).unwrap();
	let tally = walk(root, unchanged(), &mut |visit, uid, gid| {
		if visit.path == file {
			replace_with_link(&file, &secret, "file.moved");
		}
		apply(visit, uid, gid)
	})
	.unwrap();
	assert_eq!(tally.changed, 2, "the root and the file that was opened");
	let moved = std::fs::metadata(root.join("file.moved")).unwrap();
	assert_eq!(
		moved.mode() & 0o7777,
		0o4755,
		"the set-user-id bit is put back on the file that was opened"
	);
	assert_eq!(
		std::fs::metadata(&secret).unwrap().mode() & 0o7777,
		0o600,
		"the file the new name points to is untouched"
	);
	drop(outside);
}
