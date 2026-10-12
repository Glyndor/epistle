//! Account-lookup helpers on [`AccountStore`].
//!
//! Sibling so the primary `AccountStore` impl stays under the per-file
//! line budget. The methods here are the cheap lookups the CLI uses
//! before mutating anything: `account_known` is the gate the
//! destructive commands share, and `static_view` is the read path
//! `account show` uses to render the public view of a static account.

use super::AccountStore;
use crate::config::Account;

impl AccountStore {
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
