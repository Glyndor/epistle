//! A host that keeps its files in memory and records what is done to them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{Host, Scope};

/// Files in memory, one root flag, one systemd version, and a log of every
/// write, removal and reload.
pub(super) struct Fake {
	pub(super) files: BTreeMap<PathBuf, String>,
	pub(super) root: bool,
	pub(super) version: Option<u32>,
	pub(super) writes: Vec<PathBuf>,
	pub(super) removals: Vec<PathBuf>,
	pub(super) reloads: Vec<Scope>,
	pub(super) fail_reload: bool,
}

impl Fake {
	pub(super) fn new(root: bool) -> Self {
		Fake {
			files: BTreeMap::new(),
			root,
			version: Some(255),
			writes: Vec::new(),
			removals: Vec::new(),
			reloads: Vec::new(),
			fail_reload: false,
		}
	}

	/// Nothing was written, removed or reloaded.
	pub(super) fn untouched(&self) -> bool {
		self.writes.is_empty() && self.removals.is_empty() && self.reloads.is_empty()
	}
}

impl Host for Fake {
	fn read(&mut self, path: &Path) -> Result<Option<String>, String> {
		Ok(self.files.get(path).cloned())
	}
	fn write(&mut self, path: &Path, text: &str) -> Result<(), String> {
		self.writes.push(path.to_path_buf());
		self.files.insert(path.to_path_buf(), text.to_string());
		Ok(())
	}
	fn remove(&mut self, path: &Path) -> Result<bool, String> {
		self.removals.push(path.to_path_buf());
		Ok(self.files.remove(path).is_some())
	}
	fn is_root(&self) -> bool {
		self.root
	}
	fn systemd_version(&mut self) -> Option<u32> {
		self.version
	}
	fn reload(&mut self, scope: Scope) -> Result<(), String> {
		self.reloads.push(scope);
		if self.fail_reload {
			Err("Failed to connect to bus".to_string())
		} else {
			Ok(())
		}
	}
}
