//! Listing the entries of the queue, whole or a page at a time.

use std::collections::BinaryHeap;
use std::path::Path;

use uuid::Uuid;

use super::*;

/// The oldest entries of the queue after a position.
#[derive(Debug, Clone)]
pub struct Listed {
	/// Their ids, oldest first.
	pub ids: Vec<Uuid>,
	/// True when the queue holds entries after the last of them.
	pub more: bool,
}

impl FsSpool {
	/// List ids of all complete spooled messages, oldest first.
	pub fn list(&self) -> std::io::Result<Vec<Uuid>> {
		let mut ids = self.ids()?.collect::<std::io::Result<Vec<_>>>()?;
		// UUID v7 sorts chronologically.
		ids.sort();
		Ok(ids)
	}

	/// The `limit` oldest ids that come after `after` (from the start when
	/// there is none), and whether the queue holds more. The whole directory
	/// is walked, since its names come in no order, but no more than
	/// `limit + 1` ids are held at once, so the memory a page costs does not
	/// grow with the queue.
	pub fn list_after(&self, after: Option<Uuid>, limit: usize) -> std::io::Result<Listed> {
		// A max-heap: what is popped is the newest of those held.
		let mut kept = BinaryHeap::new();
		let mut more = false;
		for id in self.ids()? {
			let id = id?;
			if after.is_some_and(|anchor| id <= anchor) {
				continue;
			}
			kept.push(id);
			if kept.len() > limit {
				kept.pop();
				more = true;
			}
		}
		Ok(Listed {
			ids: kept.into_sorted_vec(),
			more,
		})
	}

	/// The ids of the complete entries, in the order the directory gives them.
	fn ids(&self) -> std::io::Result<impl Iterator<Item = std::io::Result<Uuid>>> {
		let entries = crate::util::fs_walk::rooted::read_dir(
			&self.data_dir,
			self.path_in(Path::new(SpoolDir::New.name()))?,
		)?;
		Ok(entries.filter_map(|entry| {
			let entry = match entry {
				Ok(entry) => entry,
				Err(error) => return Some(Err(error)),
			};
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				return None;
			}
			let name = entry.file_name();
			let stem = name.to_str()?.strip_suffix(".json")?;
			Uuid::parse_str(stem).ok().map(Ok)
		}))
	}
}
