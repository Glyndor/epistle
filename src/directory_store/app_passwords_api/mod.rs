//! The `AccountStore` methods that front the app-password store.
//!
//! Split out of `mod.rs` only to stay under the per-file line limit; this
//! is the same `impl` block, and every write here rebuilds the directory
//! so an app-password add or remove is visible to authentication on the
//! next request.

use super::AccountStore;
use super::StoreError;
use super::app_passwords::{AppPassword, AppPasswordStore};

#[cfg(test)]
mod tests;

impl AccountStore {
	/// Append an app password to both the disk store and the in-memory
	/// mirror, then rebuild the directory so the new credential is
	/// usable from the next authentication attempt without a server
	/// restart. The CLI surface also writes through a fresh
	/// `AppPasswordStore::open`, which is fine for a process that exits
	/// when done; the in-memory mirror matters for the long-running
	/// server path. `Duplicate` if `account` already has an entry with
	/// the same `label`.
	///
	/// The in-memory mirror is rebuilt from the post-write disk state
	/// rather than patched with the new entry alone. Another process
	/// may have added credentials while this store was open; the file
	/// keeps them, because `AppPasswordStore::add` rereads it under the
	/// `flock`, but a mirror patched with the new entry alone would not
	/// hold them, and the server would refuse them until a restart.
	pub fn add_app_password(&self, account: &str, app: AppPassword) -> Result<(), StoreError> {
		let data_dir = self.path.parent().ok_or_else(|| {
			StoreError::Invalid("account store path has no parent directory".to_string())
		})?;
		let mut disk_store = AppPasswordStore::open(data_dir)?;
		disk_store.add(account, app)?;
		// The in-memory mirror now reflects the post-write state
		// (everything that was on disk, plus the new entry, plus
		// anything a sibling writer committed between the
		// AccountStore's open and our flock).
		let mut in_memory = self.app_passwords.write().expect("app-passwords lock");
		in_memory.clear();
		in_memory.extend(disk_store.entries());
		drop(in_memory);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Remove every app password for `name` from disk *and* the in-memory
	/// mirror, then rebuild the directory so a recreated account cannot
	/// inherit the previous owner's credentials. The case-insensitive
	/// matching matches how `AppPasswordStore` keys its map. Returns the
	/// on-disk count the disk store reported. The mirror is rebuilt from
	/// the disk state after the removal, as in `add_app_password`.
	pub fn remove_all_app_passwords(&self, name: &str) -> Result<u32, StoreError> {
		let data_dir = self.path.parent().ok_or_else(|| {
			StoreError::Invalid("account store path has no parent directory".to_string())
		})?;
		let mut disk_store = AppPasswordStore::open(data_dir)?;
		let removed = disk_store.remove_account(name)?;
		let mut in_memory = self.app_passwords.write().expect("app-passwords lock");
		in_memory.clear();
		in_memory.extend(disk_store.entries());
		drop(in_memory);
		self.handle.replace(self.build_directory());
		Ok(removed)
	}

	/// The in-memory mirror's view of one account's app passwords, in
	/// insertion order, for the tests of `add_app_password` and
	/// `remove_all_app_passwords`.
	#[cfg(test)]
	pub(crate) fn for_account(&self, account: &str) -> Vec<AppPassword> {
		self.app_passwords
			.read()
			.expect("app-passwords lock")
			.iter()
			.filter(|(owner, _)| owner == &account.to_ascii_lowercase())
			.map(|(_, app)| app.clone())
			.collect()
	}
}
