//! The host restore temp directory refuses a name that is taken and clears
//! what a killed restore left behind.

use std::fs;
use std::os::unix::fs::symlink;

use super::{PREFIX, RestoreHostTemp, removable, remove_abandoned};

/// A pid that belonged to a child that has been reaped, so nothing is
/// running under it.
fn dead_pid() -> i32 {
	let mut child = std::process::Command::new("true").spawn().expect("spawn");
	let pid = child.id() as i32;
	child.wait().expect("wait");
	pid
}

/// A name that is already taken is skipped, never opened again: the file
/// that is there keeps its bytes and the new one lands on the next name.
#[test]
fn a_name_already_taken_is_skipped_and_its_bytes_kept() {
	let dir = tempfile::tempdir().unwrap();
	let taken = dir.path().join("first.sql");
	fs::write(&taken, "somebody else's bytes").unwrap();
	let mut temp = RestoreHostTemp::create_in(dir.path(), &|attempt| {
		if attempt == 0 {
			"first.sql".to_string()
		} else {
			format!("second-{attempt}.sql")
		}
	})
	.expect("the next name is free");
	temp.write_all(b"new").unwrap();
	assert_eq!(fs::read_to_string(&taken).unwrap(), "somebody else's bytes");
	assert_eq!(temp.file_name().unwrap(), "second-1.sql");
	assert_eq!(fs::read_to_string(temp.path()).unwrap(), "new");
}

/// A link planted at the name is not followed.
#[test]
fn a_link_at_the_name_is_not_followed() {
	let dir = tempfile::tempdir().unwrap();
	let target = dir.path().join("target");
	fs::write(&target, "keep").unwrap();
	symlink(&target, dir.path().join("first.sql")).unwrap();
	let mut temp = RestoreHostTemp::create_in(dir.path(), &|attempt| {
		format!("{}.sql", if attempt == 0 { "first" } else { "next" })
	})
	.expect("the next name is free");
	temp.write_all(b"new").unwrap();
	assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
}

/// A restore killed by a signal never runs its guard. The next one removes
/// what that process staged, and only that.
#[test]
fn a_file_left_by_a_dead_restore_is_removed_and_a_live_one_is_kept() {
	let dir = tempfile::tempdir().unwrap();
	let stale = dir.path().join(format!("{PREFIX}{}-1-0.sql", dead_pid()));
	let live = dir
		.path()
		.join(format!("{PREFIX}{}-1-0.sql", std::process::id()));
	let stale_dir = dir.path().join(format!("{PREFIX}{}-3-0", dead_pid()));
	fs::create_dir(&stale_dir).unwrap();
	fs::write(stale_dir.join("restore.sql"), "x").unwrap();
	let live_dir = dir
		.path()
		.join(format!("{PREFIX}{}-3-0", std::process::id()));
	fs::create_dir(&live_dir).unwrap();
	let other = dir.path().join("notes.sql");
	let linked = dir.path().join(format!("{PREFIX}{}-2-0.sql", dead_pid()));
	let target = dir.path().join("target");
	for file in [&stale, &live, &other, &target] {
		fs::write(file, "x").unwrap();
	}
	symlink(&target, &linked).unwrap();
	remove_abandoned(dir.path());
	assert!(!stale.exists(), "the file of a dead restore must go");
	assert!(live.exists(), "a restore that is running keeps its file");
	assert!(!stale_dir.exists(), "the directory of a dead restore goes");
	assert!(live_dir.exists(), "the directory of a live restore stays");
	assert!(other.exists(), "a file that is not a staged name stays");
	assert!(
		linked.symlink_metadata().is_ok() && target.exists(),
		"a link is never followed or removed"
	);
}

/// A non-root test cannot plant a file of another user, so the rule that
/// keeps a restore from deleting somebody else's file is checked on its own:
/// only a regular file of this user whose restore is gone may go.
#[test]
fn only_a_regular_file_of_this_user_with_a_dead_restore_is_removable() {
	let me = 1000;
	assert!(removable(true, me, me, false));
	assert!(
		!removable(true, 0, me, false),
		"a file of another user stays"
	);
	assert!(
		!removable(true, me, me, true),
		"a live restore keeps its file"
	);
	assert!(!removable(false, me, me, false), "a link stays");
}
