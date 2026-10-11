//! In-place mutators the `epistle account …` subcommands drive.
//!
//! Lives in a sibling so `mod.rs` stays under the per-file line
//! budget. The methods here all run against a dynamic row already on
//! disk and rebuild the directory on every call, exactly the way
//! `set_password_hash` and `set_disabled` do today.

use crate::smtp::address::Address;

use super::{AccountStore, DynamicAccount, StoreError};

impl AccountStore {
	/// Whether the named account comes from the static configuration. The
	/// CLI uses this to refuse "edit the config" hints without first
	/// attempting the mutation: the mutator returns `NotFound` either way,
	/// but the CLI wants the distinction so the error text can tell the
	/// operator where to make the change.
	pub fn is_static(&self, name: &str) -> bool {
		self.static_accounts
			.iter()
			.any(|account| account.name == name)
	}

	/// Set or clear a dynamic account's storage quota (bytes). `None`
	/// removes the per-account quota and falls back to the domain quota,
	/// then the server default, the same chain `quota_bytes = None` takes on
	/// a static account. Rebuilds the directory so the next IMAP
	/// `GETQUOTAROOT` and the next delivery quota check see the new
	/// value. Returns the previous value so the CLI can report the
	/// prior value and the new value without re-reading the file.
	/// `NotFound` for static and unknown accounts.
	pub fn set_quota_bytes(
		&self,
		name: &str,
		bytes: Option<u64>,
	) -> Result<Option<u64>, StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		let previous = account.quota_bytes;
		account.quota_bytes = bytes;
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(previous)
	}

	/// Set or clear a dynamic account's protocol allowlist. `None` lifts
	/// the restriction and every protocol authenticates again, the
	/// pre-restriction behaviour. Rebuilds the directory so the gate in
	/// `Directory::authenticate_with_ip` reflects the new restriction on
	/// the next authentication attempt. `NotFound` for static and unknown
	/// accounts.
	pub fn set_allowed_protocols(
		&self,
		name: &str,
		protocols: Option<Vec<crate::config::Protocol>>,
	) -> Result<Option<Vec<crate::config::Protocol>>, StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		let previous = account.allowed_protocols.clone();
		account.allowed_protocols = protocols;
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(previous)
	}

	/// Whether `raw` already routes somewhere: a static account, a dynamic
	/// account other than `except`, a static `[[alias]]`, or a masked
	/// address. Callers hold the dynamic write lock and pass its contents,
	/// so the check and the following write see the same accounts.
	pub(super) fn address_taken(
		&self,
		dynamic: &[DynamicAccount],
		except: Option<&str>,
		raw: &str,
	) -> bool {
		let used_by_account = self
			.static_accounts
			.iter()
			.flat_map(|existing| existing.addresses.iter())
			.chain(
				dynamic
					.iter()
					.filter(|existing| Some(existing.name.as_str()) != except)
					.flat_map(|existing| existing.addresses.iter()),
			)
			.any(|address| address.eq_ignore_ascii_case(raw));
		let used_by_alias = self
			.aliases
			.iter()
			.any(|alias| alias.address.eq_ignore_ascii_case(raw));
		let used_by_masked = self
			.masked
			.read()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(raw)
			.is_some();
		used_by_account || used_by_alias || used_by_masked
	}

	/// Add an address to a dynamic account. Runs the same domain check
	/// and conflict check `add` runs on a fresh dynamic account: a
	/// malformed address, an address outside the configured domains, or
	/// an address already routed elsewhere (another account, a static
	/// alias or a masked address) is rejected. The account must already exist; `NotFound` is the
	/// answer for static and unknown names. Rebuilds the directory so
	/// the next delivery attempt resolves the new address.
	pub fn add_address(&self, name: &str, raw: &str) -> Result<(), StoreError> {
		let address = Address::parse(raw)
			.map_err(|_| StoreError::Invalid(format!("invalid address {raw}")))?;
		if !self
			.domains
			.iter()
			.any(|domain| domain.eq_ignore_ascii_case(address.domain()))
		{
			return Err(StoreError::Invalid(format!(
				"address {raw} is not in a configured domain"
			)));
		}
		let mut dynamic = self.dynamic.write().expect("store lock");
		let existing_on_self = dynamic
			.iter()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?
			.addresses
			.iter()
			.any(|existing| existing.eq_ignore_ascii_case(raw));
		if existing_on_self || self.address_taken(&dynamic, Some(name), raw) {
			return Err(StoreError::Duplicate(raw.to_string()));
		}
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		account.addresses.push(raw.to_string());
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Remove an address from a dynamic account. Refuses to remove the
	/// last remaining address (the directory requires at least one
	/// delivery target per account). The account must already exist;
	/// `NotFound` is the answer for static and unknown names. Rebuilds
	/// the directory so the next delivery attempt rejects the removed
	/// address identically to an unknown user.
	pub fn remove_address(&self, name: &str, raw: &str) -> Result<(), StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		let position = account
			.addresses
			.iter()
			.position(|existing| existing.eq_ignore_ascii_case(raw))
			.ok_or_else(|| {
				StoreError::Invalid(format!("address {raw} is not assigned to {name}"))
			})?;
		if account.addresses.len() == 1 {
			return Err(StoreError::Invalid(
				"cannot remove the account's last address".to_string(),
			));
		}
		account.addresses.remove(position);
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}
}
