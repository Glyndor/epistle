//! The new secrets of the run in progress.
//!
//! A secret is written here, synced, before the store or the configuration
//! that will hold its hash is changed. A run killed after the change and
//! before the report still has the secret on disk, so the next run can hand
//! it over instead of rotating again to make one somebody holds. The file is
//! owner-only and removed when the run finishes and has printed them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// File name inside the rotation directory.
const FILE: &str = "secrets.json";

/// The secrets of one run, by [`super::journal::Step::secret_key`].
#[derive(Debug, Default)]
pub(in crate::cli::rotate) struct Secrets {
	path: PathBuf,
	values: BTreeMap<String, String>,
}

impl Secrets {
	/// Read the file in `dir`; a missing one is empty.
	pub(in crate::cli::rotate) fn open(dir: &Path) -> Result<Self, String> {
		let path = dir.join(FILE);
		let values = match std::fs::read(&path) {
			Ok(bytes) => serde_json::from_slice(&bytes)
				.map_err(|error| format!("cannot read {}: {error}", path.display()))?,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
			Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
		};
		Ok(Secrets { path, values })
	}

	/// The secret kept under `key`.
	pub(in crate::cli::rotate) fn get(&self, key: &str) -> Option<&str> {
		self.values.get(key).map(String::as_str)
	}

	/// Keep `secret` under `key` and write the file before returning.
	pub(in crate::cli::rotate) fn put(
		&mut self,
		key: String,
		secret: String,
	) -> Result<(), String> {
		self.values.insert(key, secret);
		let bytes = serde_json::to_vec(&self.values).map_err(|error| error.to_string())?;
		crate::storage::write_secret(&self.path, &bytes)
			.map_err(|error| format!("cannot write {}: {error}", self.path.display()))
	}

	/// Delete the file once its secrets have been handed over.
	pub(in crate::cli::rotate) fn remove(self) -> Result<(), String> {
		match std::fs::remove_file(&self.path) {
			Ok(()) => Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(error) => Err(format!("cannot remove {}: {error}", self.path.display())),
		}
	}
}

/// The sha256 of a secret, as the journal records it.
pub(in crate::cli::rotate) fn digest(secret: &str) -> String {
	crate::api::api_keys::sha256_hash(secret)
}
