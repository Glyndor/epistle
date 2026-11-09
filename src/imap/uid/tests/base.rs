//! UIDs are assigned once per message and never twice to two messages, even
//! when several scans of one mailbox run at the same time.

use super::super::resolve_uids;
use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use uuid::Uuid;

fn mailbox(count: usize) -> (tempfile::TempDir, Vec<Uuid>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ids: Vec<Uuid> = (0..count).map(|_| Uuid::now_v7()).collect();
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

#[test]
fn messages_without_a_uid_get_consecutive_ones_in_order() {
	let (dir, ids) = mailbox(5);
	assert_eq!(resolve_uids(dir.path(), &ids), vec![1, 2, 3, 4, 5]);
	// A second look reads them back and assigns nothing.
	assert_eq!(resolve_uids(dir.path(), &ids), vec![1, 2, 3, 4, 5]);
}

#[test]
fn a_message_that_arrives_later_continues_the_counter() {
	let (dir, mut ids) = mailbox(3);
	assert_eq!(resolve_uids(dir.path(), &ids), vec![1, 2, 3]);
	let late = Uuid::now_v7();
	std::fs::write(dir.path().join(format!("{late}.eml")), b"x").expect("late message");
	ids.push(late);
	assert_eq!(resolve_uids(dir.path(), &ids), vec![1, 2, 3, 4]);
}

#[test]
fn scans_at_the_same_time_never_give_one_uid_to_two_messages() {
	for _ in 0..20 {
		let (dir, ids) = mailbox(12);
		let ids = Arc::new(ids);
		let start = Arc::new(Barrier::new(8));
		let handles: Vec<_> = (0..8)
			.map(|_| {
				let (path, ids, start) = (dir.path().to_path_buf(), ids.clone(), start.clone());
				std::thread::spawn(move || {
					start.wait();
					resolve_uids(&path, &ids)
				})
			})
			.collect();
		let answers: Vec<Vec<u32>> = handles
			.into_iter()
			.map(|handle| handle.join().expect("scan"))
			.collect();
		for answer in &answers {
			assert_eq!(answer, &answers[0], "every scan sees the same UIDs");
			let distinct: HashSet<u32> = answer.iter().copied().collect();
			assert_eq!(distinct.len(), answer.len(), "{answer:?}");
		}
	}
}
