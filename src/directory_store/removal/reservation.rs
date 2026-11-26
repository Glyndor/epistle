//! The reservation a removal holds on the account it is removing.
//!
//! A removal destroys what an account holds in several steps, some of which
//! wait. It first reserves the account in `accounts.toml`, under the same lock
//! every write takes, after asking whether its caller may remove it. From then
//! on no other write changes which addresses and domains the account holds, or
//! removes it, so it cannot move to another tenant, or be removed and created
//! again, under the removal. Every other change is still taken, so a removal
//! that cannot finish leaves an account that can be suspended or reset.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use super::super::{AccountStore, DynamicAccount, DynamicFile, StoreError};

/// The removals running in this process, by account file and name.
static RUNNING: LazyLock<Mutex<HashSet<(PathBuf, String)>>> =
	LazyLock::new(|| Mutex::new(HashSet::new()));

/// Marks one removal as running until it is dropped, also when its caller
/// gives up on it half way.
pub(super) struct Running((PathBuf, String));

impl Drop for Running {
	fn drop(&mut self) {
		RUNNING
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.remove(&self.0);
	}
}

/// What a reservation gives the removal that made it.
pub(super) struct Reserved {
	/// Names this removal in the file.
	pub(super) token: String,
	/// The addresses the account held when it was reserved.
	pub(super) addresses: Vec<String>,
}

/// The accounts a write must leave where they are, each with its token, its
/// addresses and its catch-all domains.
pub(in crate::directory_store) struct Held(Vec<(String, String, DynamicAccount)>);

/// The reserved accounts of `state`, but for `removing`. A reservation whose
/// account is not in the file is dropped, so that a later account of that name
/// starts free.
pub(in crate::directory_store) fn held(state: &mut DynamicFile, removing: Option<&str>) -> Held {
	let accounts = &state.accounts;
	state
		.removals
		.retain(|name, _| accounts.iter().any(|account| &account.name == name));
	let held = state
		.removals
		.iter()
		.filter(|(name, _)| removing != Some(name.as_str()))
		.filter_map(|(name, token)| {
			let account = accounts.iter().find(|account| &account.name == name)?;
			Some((name.clone(), token.clone(), account.clone()))
		})
		.collect();
	Held(held)
}

/// Refuse a write that removed an account in `held`, changed its addresses or
/// its catch-all domains, or changed its reservation.
pub(in crate::directory_store) fn untouched(
	state: &DynamicFile,
	held: &Held,
) -> Result<(), StoreError> {
	for (name, token, before) in &held.0 {
		let in_place = state
			.accounts
			.iter()
			.find(|account| &account.name == name)
			.is_some_and(|account| {
				account.addresses == before.addresses && account.catch_all == before.catch_all
			});
		if !in_place || state.removals.get(name) != Some(token) {
			return Err(StoreError::BeingRemoved(name.clone()));
		}
	}
	Ok(())
}

impl AccountStore {
	/// Mark the removal of `name` as running, refusing a second one in this
	/// process while the first has not ended.
	pub(super) fn running_removal(&self, name: &str) -> Result<Running, StoreError> {
		let key = (self.store_path().to_path_buf(), name.to_string());
		let mut running = RUNNING.lock().unwrap_or_else(|error| error.into_inner());
		if !running.insert(key.clone()) {
			return Err(StoreError::BeingRemoved(name.to_string()));
		}
		Ok(Running(key))
	}

	/// Ask `authorize` about the account `name` as it is under the lock, and
	/// reserve it for a removal. A reservation left by a removal that did not
	/// finish is taken over.
	pub(super) fn reserve_removal(
		&self,
		name: &str,
		authorize: impl FnOnce(&DynamicAccount) -> bool,
	) -> Result<Reserved, StoreError> {
		let token = uuid::Uuid::now_v7().to_string();
		let mut addresses = Vec::new();
		self.mutate_store_except(Some(name), |state| {
			let account = state
				.accounts
				.iter()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			if !authorize(account) {
				return Err(StoreError::NotFound(name.to_string()));
			}
			addresses.clone_from(&account.addresses);
			state.removals.insert(name.to_string(), token.clone());
			Ok(())
		})?;
		Ok(Reserved { token, addresses })
	}

	/// Remove the account the removal named `token` holds, and its
	/// reservation, in one write.
	pub(super) fn remove_reserved(&self, name: &str, token: &str) -> Result<(), StoreError> {
		self.mutate_store_except(Some(name), |state| {
			if state.removals.get(name).map(String::as_str) != Some(token) {
				return Err(StoreError::BeingRemoved(name.to_string()));
			}
			let before = state.accounts.len();
			state.accounts.retain(|account| account.name != name);
			if state.accounts.len() == before {
				return Err(StoreError::NotFound(name.to_string()));
			}
			state.removals.remove(name);
			Ok(())
		})
	}
}
