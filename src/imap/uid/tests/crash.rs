//! A process killed while it assigns UIDs leaves sidecars and a counter in
//! some mix of old, new and half staged. The next scan must keep every UID
//! already on disk, hand out no UID twice and settle on one answer.
//!
//! Every cut is built on disk by hand, so the cases are exact and never depend
//! on timing: the cut is the number of sidecars that were renamed into place
//! before the kill, and the staging file the kill left beside the next one.

use super::super::{resolve_uids, write_counter, write_message};
use crate::util::path_component::{MessageExt, StateFile, message_tmp_file, state_tmp_file};
use std::collections::HashSet;
use uuid::Uuid;

const MESSAGES: usize = 4;

/// What a kill leaves in a staging file: nothing, a prefix, or all of it.
const STAGING: [&[u8]; 3] = [b"", b"1", b"7"];

fn mailbox() -> (tempfile::TempDir, Vec<Uuid>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ids: Vec<Uuid> = (0..MESSAGES).map(|_| Uuid::now_v7()).collect();
	ids.sort();
	for id in &ids {
		std::fs::write(
			dir.path().join(format!("{id}.eml")),
			b"Subject: s\r\n\r\nb\r\n",
		)
		.expect("message");
	}
	(dir, ids)
}

fn settled(dir: &std::path::Path, ids: &[Uuid], persisted: &[(Uuid, u32)], note: &str) {
	let first = resolve_uids(dir, dir, ids);
	let distinct: HashSet<u32> = first.iter().copied().collect();
	assert_eq!(
		distinct.len(),
		first.len(),
		"{note}: a UID was handed out twice"
	);
	assert!(first.iter().all(|uid| *uid > 0), "{note}: a UID is zero");
	for (id, uid) in persisted {
		let at = ids
			.iter()
			.position(|candidate| candidate == id)
			.expect("id");
		assert_eq!(first[at], *uid, "{note}: a UID on disk changed");
	}
	assert_eq!(
		resolve_uids(dir, dir, ids),
		first,
		"{note}: the answer moved"
	);
}

#[test]
fn a_kill_after_any_sidecar_leaves_no_uid_handed_out_twice() {
	for renamed in 0..=MESSAGES {
		for staging in STAGING {
			for counter_state in [None, Some(0), Some(renamed as u32)] {
				let (dir, ids) = mailbox();
				let mut persisted = Vec::new();
				for (index, id) in ids.iter().take(renamed).enumerate() {
					write_message(dir.path(), dir.path(), *id, index as u32 + 1).expect("sidecar");
					persisted.push((*id, index as u32 + 1));
				}
				if let Some(next) = ids.get(renamed) {
					let tmp = message_tmp_file(dir.path(), *next, MessageExt::Uid).expect("tmp");
					std::fs::write(tmp, staging).expect("staging");
				}
				if let Some(value) = counter_state {
					write_counter(dir.path(), dir.path(), value).expect("counter");
				}
				let note =
					format!("renamed {renamed}, staging {staging:?}, counter {counter_state:?}");
				settled(dir.path(), &ids, &persisted, &note);
			}
		}
	}
}

#[test]
fn a_counter_staging_file_left_by_a_kill_is_never_read_as_the_counter() {
	for staging in [b"" as &[u8], b"9", b"999999"] {
		let (dir, ids) = mailbox();
		let early = &ids[..2];
		assert_eq!(resolve_uids(dir.path(), dir.path(), early), vec![1, 2]);
		let tmp = state_tmp_file(dir.path(), StateFile::UidNext).expect("tmp");
		std::fs::write(tmp, staging).expect("staging");
		let all = resolve_uids(dir.path(), dir.path(), &ids);
		assert_eq!(
			all,
			vec![1, 2, 3, 4],
			"staging {staging:?} was read as state"
		);
	}
}
