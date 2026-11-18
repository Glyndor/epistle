//! The mod-sequence counter of a mailbox only goes up, one step for each caller,
//! however many callers there are at the same moment.

use super::super::next_counter;
use std::collections::HashSet;
use std::sync::{Arc, Barrier};

#[test]
fn callers_at_the_same_time_each_get_their_own_modseq() {
	for _ in 0..10 {
		let dir = tempfile::tempdir().expect("tempdir");
		let start = Arc::new(Barrier::new(8));
		let handles: Vec<_> = (0..8)
			.map(|_| {
				let (path, start) = (dir.path().to_path_buf(), start.clone());
				std::thread::spawn(move || {
					start.wait();
					(0..10)
						.map(|_| next_counter(&path, &path).expect("every caller gets a modseq"))
						.collect::<Vec<u64>>()
				})
			})
			.collect();
		let mut all: Vec<u64> = handles
			.into_iter()
			.flat_map(|handle| handle.join().expect("caller"))
			.collect();
		let distinct: HashSet<u64> = all.iter().copied().collect();
		assert_eq!(distinct.len(), all.len(), "a modseq was given twice");
		all.sort_unstable();
		let first = all[0];
		assert_eq!(
			all,
			(first..first + 80).collect::<Vec<u64>>(),
			"the counter has gaps"
		);
	}
}

#[cfg(unix)]
#[test]
fn the_root_is_the_data_dir_so_a_linked_account_is_not_trusted() {
	let data = tempfile::tempdir().expect("data");
	let outside = tempfile::tempdir().expect("outside");
	std::fs::write(outside.path().join(".modseqctr"), "41").expect("counter");
	std::fs::create_dir_all(data.path().join("accounts")).expect("mkdir");
	let account = data.path().join("accounts").join("alice");
	std::os::unix::fs::symlink(outside.path(), &account).expect("link");
	// The counter behind the link is not read: it counts as absent.
	assert_eq!(next_counter(data.path(), &account).expect("next"), 2);
}
