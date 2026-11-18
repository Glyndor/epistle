//! A process killed while it records a UIDVALIDITY leaves the account counter
//! and the mailbox file in some mix of old, new and half staged. The counter is
//! written first, so a kill between the two writes leaves it ahead of the
//! mailbox. Reopening must then never hand out a value a client may already
//! hold, and must settle on one value.

use super::super::{read_or_init, write};
use crate::util::path_component::{
	AccountName, AccountRoot, StateFile, state_file, state_tmp_file,
};
use std::path::{Path, PathBuf};

/// Far from the clock, so the cases do not depend on what time it is.
const AHEAD: u32 = u32::MAX - 101;

fn root(data: &Path) -> AccountRoot {
	std::fs::create_dir_all(data.join("accounts/alice")).unwrap();
	AccountName::new("alice").unwrap().root(data).unwrap()
}

fn folder(root: &AccountRoot) -> PathBuf {
	let dir = root.as_path().join("folders").join("box").join("new");
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

#[test]
fn a_kill_between_the_counter_and_the_mailbox_never_repeats_a_value() {
	let data = tempfile::tempdir().unwrap();
	let root = root(data.path());
	let dir = folder(&root);
	// The kill came after the counter was renamed and before the mailbox was.
	write(
		root.data_dir(),
		root.as_path(),
		StateFile::UidValidityLast,
		AHEAD,
	)
	.unwrap();
	let value = read_or_init(&dir, &root);
	assert!(value > AHEAD, "{value} is not past the counter {AHEAD}");
	assert_eq!(read_or_init(&dir, &root), value, "the value moved");
}

#[test]
fn a_kill_after_both_writes_keeps_the_value() {
	let data = tempfile::tempdir().unwrap();
	let root = root(data.path());
	let dir = folder(&root);
	write(
		root.data_dir(),
		root.as_path(),
		StateFile::UidValidityLast,
		AHEAD,
	)
	.unwrap();
	write(root.data_dir(), &dir, StateFile::UidValidity, AHEAD).unwrap();
	assert_eq!(read_or_init(&dir, &root), AHEAD);
}

#[test]
fn staging_files_a_kill_left_behind_are_never_read_as_state() {
	for staging in [b"" as &[u8], b"4", b"4294967"] {
		let data = tempfile::tempdir().unwrap();
		let root = root(data.path());
		let dir = folder(&root);
		for (place, file) in [
			(&dir, StateFile::UidValidity),
			(&root.as_path().to_path_buf(), StateFile::UidValidityLast),
		] {
			std::fs::write(state_tmp_file(place, file).unwrap(), staging).unwrap();
		}
		let value = read_or_init(&dir, &root);
		assert!(
			value > 1_000_000,
			"staging {staging:?} became the value {value}"
		);
		assert_eq!(read_or_init(&dir, &root), value);
		let stored = std::fs::read_to_string(state_file(&dir, StateFile::UidValidity).unwrap());
		assert_eq!(stored.unwrap().trim(), value.to_string());
	}
}
