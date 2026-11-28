//! The two writes that change which addresses a dynamic account holds, the
//! ones `epistle account address` and the management API make.
//!
//! Everything that decides either of them is asked under the lock of
//! `accounts.toml`, of the file as it is read there: who may write, whether
//! the address is free and how many places are left. A write by another
//! process, or by another request, is therefore counted.

use crate::util::address::normalize;
use crate::util::address_reason;

use super::{AccountStore, DynamicAccount, StoreError};

impl AccountStore {
	/// Add an address to a dynamic account. Runs the same domain check
	/// and conflict check `add` runs on a fresh dynamic account: a
	/// malformed address, an address outside the configured domains, or
	/// an address already routed elsewhere (another account, a static
	/// alias or a masked address) is rejected. So is one past the cap on
	/// addresses per account, or in the domain of a tenant that does not
	/// count the account yet and already holds as many accounts as it may.
	/// The account must already exist; `NotFound` is the answer for static
	/// and unknown names. Rebuilds the directory so the next delivery
	/// attempt resolves the new address.
	pub fn add_address(&self, name: &str, raw: &str) -> Result<(), StoreError> {
		self.add_address_if(name, raw, |_| true)
	}

	/// [`add_address`](Self::add_address) for a caller whose authority was
	/// decided before the write waited for the store's lock: `authorize` is
	/// asked about the account as it is under that lock, before anything is
	/// said about the address, and a refusal answers like an account that
	/// does not exist.
	pub fn add_address_if(
		&self,
		name: &str,
		raw: &str,
		authorize: impl FnOnce(&DynamicAccount) -> bool,
	) -> Result<(), StoreError> {
		let raw = normalize(raw);
		let raw = raw.as_str();
		let address = address_reason::parse(raw).map_err(StoreError::Invalid)?;
		self.mutate_store_hosted(|state| {
			let missing = || StoreError::NotFound(name.to_string());
			let slot = state
				.accounts
				.iter()
				.position(|account| account.name == name)
				.ok_or_else(missing)?;
			let target = &state.accounts[slot];
			if !authorize(target) {
				return Err(missing());
			}
			if !self.hosts_on_disk(address.domain())? {
				return Err(StoreError::Invalid(address_reason::not_handled(
					address.domain(),
				)));
			}
			let existing_on_self = target
				.addresses
				.iter()
				.any(|existing| normalize(existing) == raw);
			if existing_on_self || self.address_taken(&state.accounts, Some(name), raw) {
				return Err(StoreError::Duplicate(raw.to_string()));
			}
			let mut proposed = target.addresses.clone();
			proposed.push(raw.to_string());
			// Every address the account would hold names a domain the cap is
			// resolved over, as the file has them now.
			self.admit_addresses(name, &proposed, proposed.len())?;
			// A tenant the account does not count against yet takes a place
			// there, counted over the accounts the file holds now.
			self.admit_tenant_account_move(
				&target.addresses,
				&proposed,
				self.static_accounts
					.iter()
					.map(|fixed| fixed.addresses.as_slice())
					.chain(
						state
							.accounts
							.iter()
							.map(|dynamic| dynamic.addresses.as_slice()),
					),
			)?;
			state.accounts[slot].addresses = proposed;
			Ok(())
		})
	}

	/// Remove an address from a dynamic account. Refuses to remove the
	/// last remaining address (the directory requires at least one
	/// delivery target per account). The account must already exist;
	/// `NotFound` is the answer for static and unknown names. Rebuilds
	/// the directory so the next delivery attempt rejects the removed
	/// address identically to an unknown user.
	pub fn remove_address(&self, name: &str, raw: &str) -> Result<(), StoreError> {
		self.remove_address_if(name, raw, |_| true)
	}

	/// [`remove_address`](Self::remove_address) for a caller whose authority
	/// was decided before the write waited for the store's lock: `authorize`
	/// is asked about the account as it is under that lock, and a refusal
	/// answers like an account that does not exist.
	pub fn remove_address_if(
		&self,
		name: &str,
		raw: &str,
		authorize: impl FnOnce(&DynamicAccount) -> bool,
	) -> Result<(), StoreError> {
		let wanted = normalize(raw);
		self.mutate_store(|state| {
			let missing = || StoreError::NotFound(name.to_string());
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(missing)?;
			if !authorize(target) {
				return Err(missing());
			}
			let is_target = |existing: &String| normalize(existing) == wanted;
			if !target.addresses.iter().any(is_target) {
				return Err(StoreError::Invalid(format!(
					"address {raw} is not assigned to {name}"
				)));
			}
			// An account always keeps at least one delivery address.
			if target.addresses.iter().all(is_target) {
				return Err(StoreError::Invalid(
					"cannot remove the account's last address".to_string(),
				));
			}
			target.addresses.retain(|existing| !is_target(existing));
			Ok(())
		})
	}
}

#[cfg(test)]
mod tests;
