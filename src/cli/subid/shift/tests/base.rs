//! Tests for the ownership shift. The walk runs on a temporary tree with the
//! change recorded instead of applied; the real `lchown` needs privilege over
//! both blocks, so its test runs only as root, which `podman unshare` gives
//! over the caller's own subordinate block.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{IdShift, Shift, count_owned, shift_tree, walk};

const MOVE: IdShift = IdShift {
	from: 100000,
	to: 165536,
	count: 65536,
};

#[test]
fn an_id_moves_by_the_offset_only_inside_the_block() {
	assert_eq!(MOVE.map(99999), None);
	assert_eq!(MOVE.map(100000), Some(165536));
	assert_eq!(MOVE.map(100998), Some(166534));
	assert_eq!(MOVE.map(165535), Some(231071));
	assert_eq!(MOVE.map(165536), None);
	assert_eq!(MOVE.map(1000), None);
}

#[test]
fn the_reverse_shift_undoes_the_move() {
	let back = MOVE.reversed();
	for id in [100000, 100998, 165535] {
		assert_eq!(back.map(MOVE.map(id).unwrap()), Some(id));
	}
	assert_eq!(back.map(100000), None, "an unmoved id stays where it is");
}

/// The caller's own uid as a one-id block, so files a test creates are "in"
/// the moving block without any privilege.
fn mine() -> Shift {
	// SAFETY: getuid takes no arguments and cannot fail.
	let uid = unsafe { libc::getuid() };
	Shift {
		uid: Some(IdShift {
			from: uid,
			to: 4242,
			count: 1,
		}),
		gid: None,
	}
}

fn recorded(root: &Path, shift: Shift) -> Vec<(PathBuf, Option<u32>, Option<u32>)> {
	let mut seen = Vec::new();
	walk(root, shift, &mut |path, _, uid, gid| {
		seen.push((path.to_path_buf(), uid, gid));
		Ok(())
	})
	.unwrap();
	seen.sort();
	seen
}

#[test]
fn every_entry_in_the_block_is_changed_and_links_are_not_followed() {
	let outside = tempfile::tempdir().unwrap();
	std::fs::write(outside.path().join("elsewhere"), "x").unwrap();
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	std::fs::create_dir_all(root.join("volumes/pgdata")).unwrap();
	std::fs::write(root.join("volumes/pgdata/PG_VERSION"), "18").unwrap();
	std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
	let seen = recorded(root, mine());
	let paths: Vec<&Path> = seen.iter().map(|(path, _, _)| path.as_path()).collect();
	assert_eq!(
		paths,
		[
			root.to_path_buf(),
			root.join("link"),
			root.join("volumes"),
			root.join("volumes/pgdata"),
			root.join("volumes/pgdata/PG_VERSION"),
		]
	);
	assert!(
		seen.iter()
			.all(|(_, uid, gid)| *uid == Some(4242) && gid.is_none()),
		"only the uid moves, and to the shifted id: {seen:?}"
	);
}

#[test]
fn ids_outside_the_block_are_left_alone() {
	let dir = tempfile::tempdir().unwrap();
	std::fs::write(dir.path().join("file"), "x").unwrap();
	let mut shift = mine();
	shift.uid = shift.uid.map(|block| IdShift {
		from: block.from + 1,
		..block
	});
	assert!(recorded(dir.path(), shift).is_empty());
	assert_eq!(count_owned(dir.path(), Some((4242, 1)), None).unwrap(), 0);
}

#[test]
fn a_missing_root_is_an_empty_tree() {
	let dir = tempfile::tempdir().unwrap();
	let tally = shift_tree(&dir.path().join("absent"), mine()).unwrap();
	assert_eq!((tally.scanned, tally.changed), (0, 0));
}

/// Needs root over the ids 1000-1010 and 2000-2010, so it skips otherwise.
/// Run it with `podman unshare <test binary> privileged --include-ignored`.
#[test]
fn privileged_shift_keeps_set_id_bits() {
	// SAFETY: geteuid takes no arguments and cannot fail.
	if unsafe { libc::geteuid() } != 0 {
		println!("skipped: needs root over two id blocks (podman unshare)");
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let file = dir.path().join("chage");
	std::fs::write(&file, "x").unwrap();
	std::os::unix::fs::lchown(&file, Some(1000), Some(1005)).unwrap();
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o6755)).unwrap();
	let shift = Shift {
		uid: Some(IdShift {
			from: 1000,
			to: 2000,
			count: 10,
		}),
		gid: Some(IdShift {
			from: 1000,
			to: 2000,
			count: 10,
		}),
	};
	let tally = shift_tree(dir.path(), shift).unwrap();
	assert_eq!(tally.changed, 1, "only the file is in the block");
	let meta = std::fs::symlink_metadata(&file).unwrap();
	assert_eq!((meta.uid(), meta.gid()), (2000, 2005));
	assert_eq!(
		meta.mode() & 0o7777,
		0o6755,
		"lchown cleared the set-id bits and the shift must restore them"
	);
	assert_eq!(count_owned(dir.path(), Some((2000, 10)), None).unwrap(), 1);
	shift_tree(dir.path(), shift.reversed()).unwrap();
	let meta = std::fs::symlink_metadata(&file).unwrap();
	assert_eq!(
		(meta.uid(), meta.gid(), meta.mode() & 0o7777),
		(1000, 1005, 0o6755)
	);
}
