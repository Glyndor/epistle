//! Account-lookup helpers on [`AccountStore`].
//!
//! Sibling so the primary `AccountStore` impl stays under the per-file
//! line budget. The methods here are the cheap lookups the CLI uses
//! before mutating anything: `account_known` is the gate the
//! destructive commands share, and `static_view` is the read path
//! `account show` uses to render the public view of a static account.
//! [`HeldAccounts`] is the lookup for a write that has to stay true of the
//! accounts until it is on disk.

use super::{AccountStore, DynamicFile, StoreError};
use crate::config::Account;
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

/// The accounts held still, from [`AccountStore::hold_accounts`]: until this
/// is dropped no write, in this process or another, changes or removes a
/// dynamic account.
pub struct HeldAccounts<'a> {
	store: &'a AccountStore,
	file: DynamicFile,
	_lock: FileLock,
}

impl HeldAccounts<'_> {
	/// The addresses of the account `name`, static or dynamic, as
	/// `accounts.toml` has them now; `None` when there is no such account.
	pub fn addresses_of(&self, name: &str) -> Option<Vec<String>> {
		self.store
			.static_view(name)
			.map(|account| account.addresses.clone())
			.or_else(|| {
				self.file
					.accounts
					.iter()
					.find(|account| account.name == name)
					.map(|account| account.addresses.clone())
			})
	}
}

impl AccountStore {
	/// Take the lock the account writers take and read `accounts.toml` under
	/// it, for a write elsewhere that names an account. The running directory
	/// is not touched.
	///
	/// Lock order: `domains.toml`, then `accounts.toml`, then
	/// `api_keys.toml`. A thread that holds one of these locks takes only the
	/// ones after it, so this must not be called while the lock of
	/// `api_keys.toml` is held. Nor may the holder call an account writer or
	/// [`Self::reload_accounts`]: each takes this same lock again and would
	/// wait for itself.
	pub fn hold_accounts(&self) -> Result<HeldAccounts<'_>, StoreError> {
		let lock = FileLock::acquire(&lock_path(&self.path))?;
		let text = super::reload_api::read_state(&self.path)?;
		let parsed: DynamicFile =
			toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?;
		Ok(HeldAccounts {
			store: self,
			file: super::normalize::file(parsed),
			_lock: lock,
		})
	}

	/// True when `name` exists in either the static `[accounts]` table
	/// or the dynamic store. Used by the CLI to refuse destructive
	/// commands against a name nobody owns, before any side effect
	/// (password read, file write) runs.
	pub fn account_known(&self, name: &str) -> bool {
		if self.is_static(name) {
			return true;
		}
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.any(|account| account.name == name)
	}

	/// The static `[accounts]` row for `name`, when one exists. Read by
	/// `account show` to render the public view of a static account;
	/// mutators never touch this path (the `Account` shape is
	/// different on purpose, so the loader is the only writer).
	pub fn static_view(&self, name: &str) -> Option<&Account> {
		self.static_accounts
			.iter()
			.find(|account| account.name == name)
	}
}
