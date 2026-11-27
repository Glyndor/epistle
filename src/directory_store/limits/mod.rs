//! The caps the account store enforces inside its locked writes.

use std::sync::Arc;

use super::AccountStore;
use super::StoreError;
use crate::limits::{Gate, Kind, Limits, Target};

impl AccountStore {
	/// Attach the caps of the configuration and rebuild the directory, so
	/// the message-size caps reach delivery and submission and the address
	/// caps reach every write that adds one.
	pub fn with_limits(mut self, limits: Arc<Limits>) -> Self {
		self.limits = limits;
		self.rebuild_directory();
		self
	}

	/// The caps attached to this store.
	pub fn limits(&self) -> &Arc<Limits> {
		&self.limits
	}

	/// The gate of `account`: its caps, resolved over the domains of the
	/// addresses it holds now plus `also`, the domains of the addresses a
	/// write is about to add.
	pub(crate) fn gate_for<'a>(
		&self,
		account: &str,
		also: impl IntoIterator<Item = &'a str>,
	) -> Gate {
		let mut domains = self.handle.current().domains_of(account);
		domains.extend(also.into_iter().map(str::to_string));
		Gate::new(
			Arc::clone(&self.limits),
			Target::account(account, domains),
			format!("account {account}"),
		)
	}

	/// Refuse a write that would leave `account` with `total` addresses when
	/// that is past its cap. `adding` are the addresses the write brings, whose
	/// domains count among those the cap is resolved over. Called under the
	/// `accounts.toml` lock, so the count and the insert are one step.
	pub(super) fn admit_addresses(
		&self,
		account: &str,
		adding: &[String],
		total: usize,
	) -> Result<(), StoreError> {
		self.gate_for(
			account,
			adding
				.iter()
				.filter_map(|raw| raw.rsplit_once('@').map(|(_, domain)| domain)),
		)
		.admit_total(Kind::Addresses, total)
		.map_err(StoreError::Capped)
	}

	/// The gate of `account` for a command-line write, from the caps of
	/// `config` and the addresses the account holds in its data directory.
	pub fn gate_from_config(
		config: &crate::config::Config,
		account: &str,
	) -> Result<Gate, StoreError> {
		let store = Self::open(
			&config.data_dir,
			config.domains.clone(),
			config.domain_aliases.clone(),
			config.accounts.clone(),
		)?
		.with_limits(Limits::shared(config));
		Ok(store.gate_of(account))
	}

	/// The gate of `account` as it is now, for the writes that add a
	/// credential: app passwords and API keys.
	pub fn gate_of(&self, account: &str) -> Gate {
		self.gate_for(account, std::iter::empty())
	}

	/// Refuse a write that would leave a tenant with more accounts than its
	/// `max_accounts` cap allows. `existing` are the addresses of every
	/// account the store holds now: the static ones plus the dynamic ones
	/// re-read from the file under the lock, so a write from another
	/// process counts too. Called under the `accounts.toml` lock, so the
	/// count and the insert are one step.
	pub(super) fn admit_tenant_accounts<'a>(
		&self,
		addresses: &[String],
		existing: impl IntoIterator<Item = &'a [String]>,
	) -> Result<(), StoreError> {
		self.limits
			.tenant_accounts()
			.refuse_creation(addresses, existing)
			.map_or(Ok(()), |message| Err(StoreError::TenantCapped(message)))
	}

	/// [`admit_tenant_accounts`](Self::admit_tenant_accounts) for an account
	/// whose addresses change: only a tenant the account does not already
	/// count against takes a place there.
	pub(super) fn admit_tenant_account_move<'a>(
		&self,
		current: &[String],
		proposed: &[String],
		existing: impl IntoIterator<Item = &'a [String]>,
	) -> Result<(), StoreError> {
		self.limits
			.tenant_accounts()
			.refuse_move(current, proposed, existing)
			.map_or(Ok(()), |message| Err(StoreError::TenantCapped(message)))
	}
}

#[cfg(test)]
mod tests;
