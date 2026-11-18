//! A process killed while it advances the mod-sequence counter leaves the old
//! counter and a staging file beside it. The staging file is never state: the
//! next caller continues from the old value, once, and the kill costs no step.

use super::super::{next_counter, read_counter, read_message, write_message};
use crate::util::path_component::{MessageExt, StateFile, message_tmp_file, state_tmp_file};
use uuid::Uuid;

/// What a kill leaves in a staging file: nothing, a prefix, or the next value.
const STAGING: [&[u8]; 3] = [b"", b"4", b"9999"];

#[test]
fn a_counter_staging_file_a_kill_left_is_not_the_counter() {
	for staging in STAGING {
		let dir = tempfile::tempdir().expect("tempdir");
		assert_eq!(next_counter(dir.path(), dir.path()).expect("first"), 2);
		assert_eq!(next_counter(dir.path(), dir.path()).expect("second"), 3);
		let tmp = state_tmp_file(dir.path(), StateFile::ModseqCounter).expect("tmp");
		std::fs::write(tmp, staging).expect("staging");
		assert_eq!(
			read_counter(dir.path(), dir.path()),
			3,
			"staging {staging:?} was read"
		);
		assert_eq!(
			next_counter(dir.path(), dir.path()).expect("after the kill"),
			4
		);
	}
}

#[test]
fn a_message_staging_file_a_kill_left_keeps_the_old_modseq() {
	for staging in STAGING {
		let dir = tempfile::tempdir().expect("tempdir");
		let id = Uuid::now_v7();
		write_message(dir.path(), id, 5).expect("old stamp");
		let tmp = message_tmp_file(dir.path(), id, MessageExt::Modseq).expect("tmp");
		std::fs::write(tmp, staging).expect("staging");
		assert_eq!(
			read_message(dir.path(), dir.path(), id),
			5,
			"staging {staging:?} was read"
		);
		write_message(dir.path(), id, 6).expect("the retry");
		assert_eq!(read_message(dir.path(), dir.path(), id), 6);
	}
}
