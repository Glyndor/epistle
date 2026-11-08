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
						.map(|_| next_counter(&path).expect("every caller gets a modseq"))
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
