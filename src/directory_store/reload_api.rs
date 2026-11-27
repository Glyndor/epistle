//! `AccountStore` reload-from-file methods.
//!
//! Split out of `mod.rs` only to keep the per-file code-line budget
//! under control; this is the same `impl` block, and every method
//! here reloads one of the four dynamic-store files the file watcher
//! polls (`accounts.toml`, `app_passwords.toml`, `masked.json`,
//! `aliases.json`) and rebuilds the runtime directory on success.
//!
//! A parse failure returns `Invalid` without touching the in-memory
//! state, so a half-written or operator-typo'd file cannot replace the
//! running directory.
//!
//! Every method reads its file under the same cross-process lock the
//! writers take ([`crate::storage::locked::edit`]): the read and the
//! in-memory swap happen between one lock acquisition and its
//! release, so a reload can never put a state back into memory that is
//! older than the one the server just wrote. A writer that is in the
//! middle of its write makes the reload wait for it and read the
//! result; a writer that comes after the reload writes its newer
//! state over the reload's. Either way the newest state wins, and the
//! bytes on disk are the ones the mirror ends up holding.
//!
//! The lock is released before the directory is rebuilt: the rebuild
//! reads the mirrors, and a writer may hold one of them while it waits
//! for the file's lock. The rebuild always reads the current mirror,
//! so the directory never lags behind the state the swap left.
//!
//! The mirror is not written back: the bytes already live on disk
//! under the watcher, and writing them again would only churn the
//! inode.

use std::path::{Path, PathBuf};

use super::{AccountStore, StoreError};
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

/// Read the file at `path` for a reload: a missing file is the empty
/// state, not an error.
fn read_state(path: &Path) -> Result<String, StoreError> {
	match std::fs::read_to_string(path) {
		Ok(text) => Ok(text),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
		Err(error) => Err(StoreError::Io(error)),
	}
}

impl AccountStore {
	/// The path of a dynamic-store file under the store's data directory.
	pub(super) fn dynamic_file(&self, name: &str) -> PathBuf {
		self.data_dir().join(name)
	}

	/// Take the writers' lock on `path`: the same lock the mutators
	/// take before they write the file, so a reload and a write never
	/// overlap.
	fn lock_of(path: &Path) -> Result<FileLock, StoreError> {
		FileLock::acquire(&lock_path(path)).map_err(StoreError::Io)
	}

	/// Swap the dynamic-account set from `accounts.toml`, the file the
	/// account mutators write. Re-parses the file format the CLI
	/// produces and rebuilds the directory so a row the CLI added (or
	/// removed) reaches the next request without a server restart.
	///
	/// The read and the swap happen under the writers' lock, so the
	/// mirror can never end up holding a state older than the last
	/// write: an account the server just suspended stays suspended
	/// even if the watcher had read the file before that write.
	pub fn reload_accounts(&self) -> Result<(), StoreError> {
		let _lock = Self::lock_of(&self.path)?;
		let text = read_state(&self.path)?;
		let parsed: super::DynamicFile =
			toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		*self.dynamic.write().expect("store lock") = super::normalize::file(parsed).accounts;
		drop(_lock);
		self.rebuild_directory();
		Ok(())
	}

	/// Swap the in-memory app-password mirror from
	/// `app_passwords.toml`. Re-parses the file format the CLI
	/// produces and rebuilds the directory so a fresh credential (or a
	/// revocation) reaches the SMTP / IMAP authentication paths without
	/// a server restart.
	pub fn reload_app_passwords(&self) -> Result<(), StoreError> {
		let path = self.dynamic_file("app_passwords.toml");
		let _lock = Self::lock_of(&path)?;
		let text = read_state(&path)?;
		let parsed: super::app_passwords::AppPasswordFile =
			toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		let mut in_memory = self.app_passwords.write().expect("app-passwords lock");
		in_memory.clear();
		for (name, entry) in parsed.accounts {
			for app in entry.passwords {
				in_memory.push((name.to_ascii_lowercase(), app));
			}
		}
		drop(in_memory);
		drop(_lock);
		self.rebuild_directory();
		Ok(())
	}

	/// Swap the in-memory masked-address store from `masked.json`.
	/// Re-uses the on-disk schema so the watcher sees exactly what the
	/// CLI wrote.
	///
	/// The mirror's lock comes first here, the other way round from the
	/// account reload: the masked writers hold the mirror's lock and
	/// take the file's lock inside it, so the reload takes them in the
	/// same order. The two cannot deadlock, and the file cannot move
	/// under the reload either way.
	pub fn reload_masked(&self) -> Result<(), StoreError> {
		let path = self.dynamic_file("masked.json");
		let mut mirror = self.masked.write().expect("masked lock");
		let _lock = Self::lock_of(&path)?;
		let text = read_state(&path)?;
		let parsed: super::masked::MaskedFile =
			serde_json::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		mirror.replace_entries(parsed.addresses);
		drop(mirror);
		drop(_lock);
		self.rebuild_directory();
		Ok(())
	}

	/// Swap the in-memory alias disabled-overlay from `aliases.json`.
	/// The aliases themselves still live in the static config; this
	/// overlay only toggles the enabled flag, so a swap re-enables or
	/// re-disables them on the next directory build.
	pub fn reload_disabled_aliases(&self) -> Result<(), StoreError> {
		let path = self.dynamic_file("aliases.json");
		let _lock = Self::lock_of(&path)?;
		let text = read_state(&path)?;
		let parsed: super::aliases::DisabledAliasesFile =
			serde_json::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		let lower = parsed
			.addresses
			.into_iter()
			.map(|address| address.to_ascii_lowercase())
			.collect();
		self.aliases_disabled
			.write()
			.expect("aliases lock")
			.replace_disabled(lower);
		drop(_lock);
		self.rebuild_directory();
		Ok(())
	}
}
