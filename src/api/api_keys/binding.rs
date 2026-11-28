//! Writing a key that may be bound to an account.

use std::io::{Error, ErrorKind};

use super::issue::{Ask, World};
use super::{ApiKey, ApiKeyStore};
use crate::directory_store::{AccountStore, HeldAccounts, StoreError};
use crate::limits::Gate;

/// The server while the accounts are held: accounts as `accounts.toml` has
/// them, and the rest as `rest` answers.
struct Held<'a, 'store> {
	accounts: &'a HeldAccounts<'store>,
	rest: &'a dyn World,
}

impl World for Held<'_, '_> {
	fn account_known(&self, name: &str) -> bool {
		self.accounts.addresses_of(name).is_some()
	}

	fn account_addresses(&self, name: &str) -> Vec<String> {
		self.accounts.addresses_of(name).unwrap_or_default()
	}

	fn hosts(&self, domain: &str) -> bool {
		self.rest.hosts(domain)
	}
}

impl ApiKeyStore {
	/// Add `key`, which may be bound to an account of `accounts`, as
	/// [`Self::add_within`] does, or as [`Self::add_by`] does when `by` names
	/// the key that asks.
	///
	/// For a bound key `accounts.toml` is held from the read of the account to
	/// the write of the key, so no other write, in this process or another,
	/// moves or removes the account in between. The account is read as the
	/// file has it then: one that is not there is `InvalidInput` and nothing
	/// is written, and the key that asks is judged by the addresses it has
	/// then. The lock of `accounts.toml` is taken before the one of
	/// `api_keys.toml` (see [`AccountStore::hold_accounts`]).
	pub fn add_bound(
		&mut self,
		key: ApiKey,
		gate: Option<&Gate>,
		by: Option<Ask<'_>>,
		accounts: &AccountStore,
	) -> std::io::Result<()> {
		let Some(name) = key.account.clone() else {
			return self.add_inner(key, gate, by);
		};
		let held = accounts.hold_accounts().map_err(|error| match error {
			StoreError::Io(error) => error,
			other => Error::other(other.to_string()),
		})?;
		let Some(ask) = by else {
			if held.addresses_of(&name).is_none() {
				return Err(Error::new(
					ErrorKind::InvalidInput,
					format!("--account {name}: no such account"),
				));
			}
			return self.add_inner(key, gate, None);
		};
		let world = Held {
			accounts: &held,
			rest: ask.world,
		};
		self.add_inner(
			key,
			gate,
			Some(Ask {
				world: &world,
				..ask
			}),
		)
	}
}
