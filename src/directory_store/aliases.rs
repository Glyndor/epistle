//! Disabled-overlay store for multi-target aliases.
//!
//! Multi-target aliases are configured in `alias = [...]` and live in the
//! config file. When one is being abused the operator needs to disable it
//! without restarting and without editing the config — same model as
//! [`super::masked`]: a flag the directory consults, persisted across
//! restarts so the disabled state survives a reload.
//!
//! This module holds only the **disabled** set. The aliases themselves are
//! still sourced from the config; the store overlays the enabled flag on
//! top of them. A disabled alias is absent from the directory's `aliases`
//! map, so it falls through to the next step of [`crate::smtp::directory::Directory::resolve`]
//! (the masked-address step, then sub-addressing, then catch-all) — exactly
//! the way a disabled masked address falls through. The rejection response
//! is therefore indistinguishable from one for an address that never
//! existed; the disabled overlay never leaks that one once did.
//!
//! Persistence mirrors [`super::masked`]: a single JSON file under
//! `{data_dir}/aliases.json`, written atomically with owner-only (`0600`)
//! permissions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{AccountStore, StoreError};

/// The on-disk JSON document: every **disabled** multi-target alias address,
/// lowercased. A missing file is an empty disabled set, which is the
/// default the config starts in.
#[derive(Debug, Default, Serialize, Deserialize)]
struct DisabledAliasesFile {
	#[serde(default)]
	addresses: Vec<String>,
}

/// Filesystem-backed overlay that tracks which multi-target aliases are
/// currently disabled. The aliases themselves come from the static config;
/// this store only marks some of them off.
pub struct AliasStore {
	path: PathBuf,
	/// Lowercased alias addresses that are currently disabled. Address keys
	/// are kept lowercased so case-insensitive lookups are exact matches
	/// against the same form the directory uses.
	disabled: HashSet<String>,
}

impl AliasStore {
	/// Open (loading if present) the overlay under `data_dir`. A missing
	/// file is an empty overlay: every configured alias starts enabled.
	pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
		let path = data_dir.join("aliases.json");
		let disabled = match std::fs::read_to_string(&path) {
			Ok(text) => {
				let file: DisabledAliasesFile = serde_json::from_str(&text)
					.map_err(|error| StoreError::Invalid(error.to_string()))?;
				file.addresses
					.into_iter()
					.map(|address| address.to_ascii_lowercase())
					.collect()
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
			Err(error) => return Err(error.into()),
		};
		Ok(Self { path, disabled })
	}

	/// Whether `address` (any case) is currently disabled.
	pub fn is_disabled(&self, address: &str) -> bool {
		self.disabled.contains(&address.to_ascii_lowercase())
	}

	/// Every disabled address, lowercased. Cheap snapshot for the
	/// directory builder's filter step.
	pub fn disabled_addresses(&self) -> impl Iterator<Item = &str> {
		self.disabled.iter().map(String::as_str)
	}

	/// Toggle the disabled flag for `address`. Returns the previous state
	/// so callers can detect a no-op. The address is lowercased on the way
	/// in to match every other lookup in the directory.
	///
	/// Persists on every state change. Setting the same value twice is a
	/// no-op and does not rewrite the file — matches how
	/// [`super::masked::MaskedAddressStore::set_enabled`] short-circuits.
	pub fn set_enabled(&mut self, address: &str, enabled: bool) -> Result<bool, StoreError> {
		let key = address.to_ascii_lowercase();
		let was_disabled = self.disabled.contains(&key);
		if enabled && was_disabled {
			self.disabled.remove(&key);
			self.persist()?;
		} else if !enabled && !was_disabled {
			self.disabled.insert(key);
			self.persist()?;
		}
		Ok(was_disabled)
	}

	/// Atomically rewrite the backing JSON file (write-temp-then-rename,
	/// mode `0600`). Sorted on the way out so the file is stable across
	/// rewrites and diff-friendly.
	fn persist(&self) -> Result<(), StoreError> {
		let mut addresses: Vec<&String> = self.disabled.iter().collect();
		addresses.sort();
		let file = DisabledAliasesFile {
			addresses: addresses.into_iter().cloned().collect(),
		};
		let text = serde_json::to_string_pretty(&file)
			.map_err(|error| StoreError::Invalid(error.to_string()))?;
		crate::storage::write_secret(&self.path, text.as_bytes())?;
		Ok(())
	}
}

#[cfg(test)]
#[path = "aliases_tests.rs"]
mod tests;

impl AccountStore {
	/// Toggle the disabled flag on the multi-target alias at `address`. A
	/// disabled alias is absent from the directory's `aliases` map, so it
	/// falls through to the next step of `Directory::resolve` and rejects
	/// like one that never existed. Returns the previous state.
	pub fn set_alias_enabled(&self, address: &str, enabled: bool) -> Result<bool, StoreError> {
		let previous = self
			.aliases_disabled
			.write()
			.expect("aliases lock")
			.set_enabled(address, enabled)?;
		self.handle.replace(self.build_directory());
		Ok(previous)
	}

	/// Whether the multi-target alias at `address` is currently disabled.
	pub fn alias_is_disabled(&self, address: &str) -> bool {
		self.aliases_disabled
			.read()
			.expect("aliases lock")
			.is_disabled(address)
	}
}
