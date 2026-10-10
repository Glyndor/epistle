//! `AccountStore` reload-from-file methods.
//!
//! Split out of `mod.rs` only to keep the per-file code-line budget
//! under control; this is the same `impl` block, and every method
//! here parses one of the four dynamic-store files the file watcher
//! polls (`accounts.toml`, `app_passwords.toml`, `masked.json`,
//! `aliases.json`) and rebuilds the runtime directory on success.
//!
//! A parse failure returns `Invalid` without touching the in-memory
//! state, so a half-written or operator-typo'd file cannot replace the
//! running directory. The reload path mirrors what the in-server
//! mutators (`add`, `remove`, `set_password_hash`, ...) do via
//! `persist` + `replace(build_directory())` but skips the persist step:
//! the bytes already live on disk under the watcher, and writing them
//! back would only churn the inode.

use super::{AccountStore, StoreError};

impl AccountStore {
	/// Swap the dynamic-account set from `text`, the contents of
	/// `accounts.toml`. Parses without persisting (the caller already
	/// wrote the bytes) and rebuilds the directory so the swap is
	/// visible to the next request. Used by the file watcher, which
	/// sees writes from sibling processes (the CLI); the in-server
	/// mutators (`add`, `remove`, `set_password_hash`, ...) go through
	/// the regular `persist` + `replace` path.
	pub fn reload_accounts_from(&self, text: &str) -> Result<(), StoreError> {
		let parsed: super::DynamicFile =
			toml::from_str(text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		*self.dynamic.write().expect("store lock") = parsed.accounts;
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Swap the in-memory app-password mirror from `text`, the contents
	/// of `app_passwords.toml`. Re-parses the file format the CLI
	/// produces and rebuilds the directory so a fresh credential
	/// (or a revocation) reaches the SMTP / IMAP authentication paths
	/// without a server restart.
	pub fn reload_app_passwords_from(&self, text: &str) -> Result<(), StoreError> {
		let parsed: super::app_passwords::AppPasswordFile =
			toml::from_str(text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		let mut in_memory = self.app_passwords.write().expect("app-passwords lock");
		in_memory.clear();
		for (name, entry) in parsed.accounts {
			for app in entry.passwords {
				in_memory.push((name.to_ascii_lowercase(), app));
			}
		}
		drop(in_memory);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Swap the in-memory masked-address store from `text`, the
	/// contents of `masked.json`. Re-uses the on-disk schema so the
	/// watcher sees exactly what the CLI wrote.
	pub fn reload_masked_from(&self, text: &str) -> Result<(), StoreError> {
		let parsed: super::masked::MaskedFile =
			serde_json::from_str(text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		self.masked
			.write()
			.expect("masked lock")
			.replace_entries(parsed.addresses);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Swap the in-memory alias disabled-overlay from `text`, the
	/// contents of `aliases.json`. The aliases themselves still live
	/// in the static config; this overlay only toggles the enabled
	/// flag, so a swap re-enables or re-disables them on the next
	/// directory build.
	pub fn reload_aliases_from(&self, text: &str) -> Result<(), StoreError> {
		let parsed: super::aliases::DisabledAliasesFile =
			serde_json::from_str(text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		let lower = parsed
			.addresses
			.into_iter()
			.map(|address| address.to_ascii_lowercase())
			.collect();
		self.aliases_disabled
			.write()
			.expect("aliases lock")
			.replace_disabled(lower);
		self.handle.replace(self.build_directory());
		Ok(())
	}
}
