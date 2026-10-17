//! The index kept beside an account's scripts: a stable id and a revision
//! for each, and a counter of changes.
//!
//! The scripts themselves are the files; the index only adds what a file
//! name cannot give. It is rebuilt from the directory whenever the two
//! disagree (a script a person dropped in gets an id, one taken out leaves
//! the index), and an index that cannot be read is the same as none, so the
//! worst a damaged one costs is fresh ids.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The largest index file that is read. Fifty entries are a few kilobytes;
/// anything bigger was not written by this code.
const MAX_INDEX_BYTES: u64 = 1 << 20;

/// What the index knows about one script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Entry {
	pub(super) id: String,
	pub(super) rev: u64,
}

impl Entry {
	fn new() -> Self {
		Self {
			id: uuid::Uuid::now_v7().simple().to_string(),
			rev: 1,
		}
	}
}

/// Every script's entry by name, and the change counter.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Index {
	pub(super) state: u64,
	pub(super) scripts: BTreeMap<String, Entry>,
}

impl Index {
	/// The index at `path`, or an empty one when it is missing, too big or
	/// not valid.
	pub(super) fn read(path: &Path) -> Self {
		let Ok(meta) = std::fs::metadata(path) else {
			return Self::default();
		};
		if meta.len() > MAX_INDEX_BYTES {
			return Self::default();
		}
		std::fs::read_to_string(path)
			.ok()
			.and_then(|text| serde_json::from_str(&text).ok())
			.unwrap_or_default()
	}

	pub(super) fn save(&self, path: &Path) -> std::io::Result<()> {
		let text = serde_json::to_string(self).map_err(std::io::Error::other)?;
		crate::storage::write_secret(path, text.as_bytes())
	}

	/// Make the index agree with the scripts `on_disk`: a script without an
	/// entry gets one, an entry without a script goes. `true` when anything
	/// changed.
	pub(super) fn reconcile(&mut self, on_disk: &BTreeSet<String>) -> bool {
		let before = self.scripts.len();
		self.scripts.retain(|name, _| on_disk.contains(name));
		let mut changed = self.scripts.len() != before;
		for name in on_disk {
			if !self.scripts.contains_key(name) {
				self.scripts.insert(name.clone(), Entry::new());
				changed = true;
			}
		}
		changed
	}

	/// Record that `name` was written: a new script gets a new id, an
	/// existing one its next revision.
	pub(super) fn wrote(&mut self, name: &str) {
		match self.scripts.get_mut(name) {
			Some(entry) => entry.rev += 1,
			None => {
				self.scripts.insert(name.to_string(), Entry::new());
			}
		}
	}

	/// Move the entry of `old` to `new`, keeping its id and revision.
	pub(super) fn renamed(&mut self, old: &str, new: &str) {
		if let Some(entry) = self.scripts.remove(old) {
			self.scripts.insert(new.to_string(), entry);
		}
	}
}
