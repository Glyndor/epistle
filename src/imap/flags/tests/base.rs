//! Two STOREs of one message at the same moment both succeed, and the sidecar
//! holds one complete answer, never a mix and never an error for the loser.

use super::super::{read_flags, write_flags};
use crate::imap::mailbox::Flag;
use std::sync::{Arc, Barrier};
use uuid::Uuid;

#[test]
fn writers_at_the_same_time_all_succeed_and_leave_one_whole_answer() {
	for _ in 0..20 {
		let dir = tempfile::tempdir().expect("tempdir");
		let id = Uuid::now_v7();
		let start = Arc::new(Barrier::new(8));
		let handles: Vec<_> = (0..8)
			.map(|n| {
				let (path, start) = (dir.path().to_path_buf(), start.clone());
				std::thread::spawn(move || {
					let flags = if n % 2 == 0 {
						vec![Flag::Seen]
					} else {
						vec![Flag::Deleted, Flag::Flagged]
					};
					start.wait();
					write_flags(&path, id, &flags)
				})
			})
			.collect();
		for handle in handles {
			handle
				.join()
				.expect("writer")
				.expect("a writer lost its rename to a sibling");
		}
		let flags = read_flags(dir.path(), id);
		assert!(
			flags == vec![Flag::Seen] || flags == vec![Flag::Deleted, Flag::Flagged],
			"{flags:?}"
		);
	}
}
