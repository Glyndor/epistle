//! The order of the locks that are held while another one of them is taken,
//! checked in tests: `domains.toml`, then `accounts.toml`, then
//! `api_keys.toml`, of one data directory. A thread that asks for one of them
//! while it holds it or a later one panics, instead of leaving two threads to
//! wait for each other one day.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// The lock files, outermost first.
const ORDER: [&str; 3] = [
	".domains.toml.lock",
	".accounts.toml.lock",
	".api_keys.toml.lock",
];

thread_local! {
	/// The ordered locks this thread holds: directory and place in the order.
	static HELD: RefCell<Vec<(PathBuf, usize)>> = const { RefCell::new(Vec::new()) };
}

/// The place a held lock takes in the order, given back when it is dropped.
#[derive(Debug, Default)]
pub(crate) struct Ranked(Option<(PathBuf, usize)>);

/// Note that this thread is about to wait for the lock file `path`.
pub(super) fn taking(path: &Path) -> Ranked {
	let rank = path
		.file_name()
		.and_then(|name| ORDER.iter().position(|ordered| name == *ordered));
	let (Some(rank), Some(dir)) = (rank, path.parent()) else {
		return Ranked(None);
	};
	let later = HELD.with_borrow(|held| {
		held.iter()
			.find(|(other, place)| other == dir && *place >= rank)
			.map(|(_, place)| *place)
	});
	if let Some(later) = later {
		panic!(
			"lock order: {} asked for while {} is held",
			ORDER[rank], ORDER[later]
		);
	}
	HELD.with_borrow_mut(|held| held.push((dir.to_path_buf(), rank)));
	Ranked(Some((dir.to_path_buf(), rank)))
}

impl Drop for Ranked {
	fn drop(&mut self) {
		let Some(mine) = self.0.take() else {
			return;
		};
		HELD.with_borrow_mut(|held| {
			if let Some(at) = held.iter().rposition(|entry| *entry == mine) {
				held.remove(at);
			}
		});
	}
}
