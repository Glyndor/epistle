//! The `AccountStore` methods that front the masked-address store, plus
//! the account projection the API layer reads.
//! Split out of `mod.rs` only to stay under the per-file line limit; this
//! is the same `impl` block, and every write here rebuilds the directory
//! so a mask starts (or stops) resolving in the same call.

use std::sync::{Arc, RwLock};

use super::{AccountStore, MaskedAddress, MaskedAddressStore, MaskedAddressView, StoreError};

impl AccountStore {
	/// Shared handle to the masked-address store, for the API surface (and
	/// tests). Mutations through the handle persist and rebuild the directory
	/// on the way back, exactly as the methods below do.
	pub fn masked_handle(&self) -> Arc<RwLock<MaskedAddressStore>> {
		Arc::clone(&self.masked)
	}

	/// Snapshot of an account's masked addresses for the API list view.
	pub fn list_masked(&self, account: &str) -> Vec<MaskedAddressView> {
		self.masked
			.read()
			.expect("masked lock")
			.list_for_account(account)
	}

	/// Create a new masked address for `account` in `domain`. The per-account
	/// limit is enforced; the random suffix comes from the CSPRNG.
	pub fn add_masked(
		&self,
		account: &str,
		label: &str,
		domain: &str,
		now: u64,
	) -> Result<MaskedAddress, StoreError> {
		let entry = self
			.masked
			.write()
			.expect("masked lock")
			.add(account, label, domain, now)?;
		self.handle.replace(self.build_directory());
		Ok(entry)
	}

	/// Toggle the `enabled` flag on `address` owned by `account`.
	pub fn set_masked_enabled(
		&self,
		account: &str,
		address: &str,
		enabled: bool,
	) -> Result<bool, StoreError> {
		let previous = self
			.masked
			.write()
			.expect("masked lock")
			.set_enabled(account, address, enabled)?;
		self.handle.replace(self.build_directory());
		Ok(previous)
	}

	/// Remove `address` owned by `account`. `NotFound` if absent or owned by
	/// someone else.
	pub fn remove_masked(&self, account: &str, address: &str) -> Result<(), StoreError> {
		self.masked
			.write()
			.expect("masked lock")
			.remove(account, address)?;
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Remove every masked address owned by `account`. Returns the number
	/// removed. Used by
	/// [`crate::directory_store::removal::remove_account`] to drop an
	/// account's whole footprint without enumerating addresses one at a
	/// time; the directory is rebuilt so the next resolution cycle stops
	/// seeing the masks immediately.
	pub fn remove_all_masked(&self, account: &str) -> Result<u32, StoreError> {
		let removed = self
			.masked
			.write()
			.expect("masked lock")
			.remove_all_for_account(account)?;
		if removed > 0 {
			self.handle.replace(self.build_directory());
		}
		Ok(removed)
	}

	/// Best-effort touch of `last_used_at` on a successful delivery. Errors
	/// are logged and swallowed; the SMTP path must not stall on the
	/// metadata update.
	pub fn touch_masked_last_used(&self, account: &str, address: &str, now: u64) {
		self.masked
			.write()
			.expect("masked lock")
			.touch_last_used(account, address, now);
	}

	/// Set the per-account cap on masked email addresses. 0 disables the cap.
	/// Called once at startup with the configured value; the directory is
	/// rebuilt so the next resolution cycle reflects the new limit on reads.
	pub fn with_masked_max(self, max: usize) -> Self {
		self.masked
			.write()
			.expect("masked lock")
			.set_max_per_account(max);
		self.handle.replace(self.build_directory());
		self
	}

	/// Account views (name + addresses) across static and dynamic accounts.
	pub fn account_views(&self) -> Vec<(String, Vec<String>, bool)> {
		let dynamic = self.dynamic.read().expect("store lock");
		let mut views: Vec<(String, Vec<String>, bool)> = self
			.static_accounts
			.iter()
			.map(|account| (account.name.clone(), account.addresses.clone(), false))
			.collect();
		views.extend(
			dynamic
				.iter()
				.map(|account| (account.name.clone(), account.addresses.clone(), true)),
		);
		views
	}
}
