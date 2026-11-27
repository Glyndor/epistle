//! In-place mutators the `epistle account …` subcommands drive.
//!
//! Lives in a sibling so `mod.rs` stays under the per-file line
//! budget. The methods here all run through
//! [`AccountStore::mutate_store`] so the cross-process `flock` and
//! the "re-read before mutate" check the rest of the dynamic mutators
//! apply are inherited for free.

use crate::util::address::normalize;
use crate::util::address_reason;

use super::{AccountChanges, AccountStore, DynamicAccount, NewPassword, StoreError};

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
		let mut previous = None;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			previous = Some(target.quota_bytes);
			target.quota_bytes = bytes;
			Ok(())
		})?;
		Ok(previous.expect("closure ran"))
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
		let mut previous: Option<Option<Vec<crate::config::Protocol>>> = None;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			previous = Some(target.allowed_protocols.clone());
			target.allowed_protocols = protocols;
			Ok(())
		})?;
		Ok(previous.expect("closure ran"))
	}

	/// Set or clear a dynamic account's `save_sent` preference.
	/// `Some(true)` enables the save (the default for accounts
	/// written before the field existed), `Some(false)` opts out.
	/// The mutator keeps the account field a tri-state so a future
	/// "inherit" value can land without breaking the on-disk
	/// format; today the helper accepts only the two boolean
	/// values. `NotFound` for static and unknown accounts.
	pub fn set_save_sent(&self, name: &str, value: bool) -> Result<Option<bool>, StoreError> {
		let mut previous: Option<Option<bool>> = None;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			previous = Some(target.save_sent);
			target.save_sent = Some(value);
			Ok(())
		})?;
		Ok(previous.expect("closure ran"))
	}

	/// Every address held by an account the SQL or LDAP backend loaded.
	pub(super) fn directory_addresses(&self) -> impl Iterator<Item = String> {
		let sql = self.sql_accounts.read().unwrap_or_else(|p| p.into_inner());
		let ldap = self.ldap_accounts.read().unwrap_or_else(|p| p.into_inner());
		let mut all: Vec<String> = Vec::new();
		all.extend(sql.iter().flat_map(|a| a.addresses.iter().cloned()));
		all.extend(ldap.iter().flat_map(|a| a.addresses.iter().cloned()));
		all.into_iter()
	}

	/// Every account name the SQL or LDAP backend loaded.
	pub(super) fn directory_names(&self) -> impl Iterator<Item = String> {
		let sql = self.sql_accounts.read().unwrap_or_else(|p| p.into_inner());
		let ldap = self.ldap_accounts.read().unwrap_or_else(|p| p.into_inner());
		let mut all: Vec<String> = Vec::new();
		all.extend(sql.iter().map(|a| a.name.clone()));
		all.extend(ldap.iter().map(|a| a.name.clone()));
		all.into_iter()
	}

	/// Whether `raw` already routes somewhere: a static account, a dynamic
	/// account other than `except`, an account from the SQL or LDAP
	/// directory, a static `[[alias]]`, or a masked address. Callers are
	/// inside the locked mutate closure, so the check and the following
	/// write see the same accounts.
	pub(super) fn address_taken(
		&self,
		dynamic: &[DynamicAccount],
		except: Option<&str>,
		raw: &str,
	) -> bool {
		let forms = claim_forms(raw);
		let wanted = normalize(raw);
		let same = |address: &String| forms.contains(&normalize(address));
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
			.any(same);
		let used_by_directory = self.directory_addresses().any(|address| same(&address));
		let used_by_alias = self
			.aliases
			.read()
			.expect("aliases lock")
			.iter()
			.any(|alias| same(&alias.address));
		let used_by_masked = self
			.masked
			.read()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(&wanted)
			.is_some();
		used_by_account || used_by_directory || used_by_alias || used_by_masked
	}

	/// Add an address to a dynamic account. Runs the same domain check
	/// and conflict check `add` runs on a fresh dynamic account: a
	/// malformed address, an address outside the configured domains, or
	/// an address already routed elsewhere (another account, a static
	/// alias or a masked address) is rejected. The account must already
	/// exist; `NotFound` is the answer for static and unknown names.
	/// Rebuilds the directory so the next delivery attempt resolves the
	/// new address.
	pub fn add_address(&self, name: &str, raw: &str) -> Result<(), StoreError> {
		let raw = normalize(raw);
		let raw = raw.as_str();
		let address = address_reason::parse(raw).map_err(StoreError::Invalid)?;
		self.mutate_store_hosted(|state| {
			if !self.hosts_on_disk(address.domain())? {
				return Err(StoreError::Invalid(address_reason::not_handled(
					address.domain(),
				)));
			}
			let existing_on_self = state
				.accounts
				.iter()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?
				.addresses
				.iter()
				.any(|existing| normalize(existing) == raw);
			if existing_on_self || self.address_taken(&state.accounts, Some(name), raw) {
				return Err(StoreError::Duplicate(raw.to_string()));
			}
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			self.admit_addresses(name, &[raw.to_string()], target.addresses.len() + 1)?;
			target.addresses.push(raw.to_string());
			Ok(())
		})?;
		Ok(())
	}

	/// Remove an address from a dynamic account. Refuses to remove the
	/// last remaining address (the directory requires at least one
	/// delivery target per account). The account must already exist;
	/// `NotFound` is the answer for static and unknown names. Rebuilds
	/// the directory so the next delivery attempt rejects the removed
	/// address identically to an unknown user.
	pub fn remove_address(&self, name: &str, raw: &str) -> Result<(), StoreError> {
		let wanted = normalize(raw);
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
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
		})?;
		Ok(())
	}

	// === Account lifecycle =================================================
	//
	// The mutators below are simple lookup-and-overwrite calls that the
	// CLI, the management API, and SCIM drive. They keep their previous
	// state where it matters (set_disabled, set_quota_bytes,
	// set_allowed_protocols above all do) so the caller can report the
	// prior value without re-reading the file.

	/// Remove a dynamic account. Static accounts cannot be removed here.
	pub fn remove(&self, name: &str) -> Result<(), StoreError> {
		self.mutate_store(|state| {
			let before = state.accounts.len();
			state.accounts.retain(|account| account.name != name);
			if state.accounts.len() == before {
				return Err(StoreError::NotFound(name.to_string()));
			}
			Ok(())
		})?;
		Ok(())
	}

	/// Replace the password hash (and SCRAM credentials) of a dynamic
	/// account. `hash` is already argon2id; `scram` is whatever the
	/// storage layer derived under the password policy at set-time.
	pub fn set_password_hash(
		&self,
		name: &str,
		hash: String,
		scram: Option<crate::smtp::scram::ScramStored>,
	) -> Result<(), StoreError> {
		self.set_password_hash_if(name, hash, scram, |_| true)
	}

	/// [`set_password_hash`](Self::set_password_hash) for a caller whose
	/// reach over the account was decided before the password was derived:
	/// `authorize` is asked about the account as it is under the store's
	/// lock, just before it is changed, and a refusal answers like an
	/// account that does not exist, with the credentials untouched. The
	/// account may have moved out of the caller's reach in between.
	pub fn set_password_hash_if(
		&self,
		name: &str,
		hash: String,
		scram: Option<crate::smtp::scram::ScramStored>,
		authorize: impl FnOnce(&DynamicAccount) -> bool,
	) -> Result<(), StoreError> {
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			if !authorize(target) {
				return Err(StoreError::NotFound(name.to_string()));
			}
			target.password_hash = hash;
			target.scram = scram;
			target.rehashed = None;
			super::credential_reset::password_replaced(target);
			Ok(())
		})?;
		Ok(())
	}

	/// Apply several changes to a dynamic account in one write, for a caller
	/// whose reach over the account was decided before the changes were
	/// prepared: `authorize` is asked about the account as it is under the
	/// store's lock. Either every change is written or none is: a value the
	/// store refuses, a refusal or an unknown account leaves it as it was.
	/// Returns the account as it was just before the write.
	pub fn change_account_if(
		&self,
		name: &str,
		changes: AccountChanges,
		authorize: impl FnOnce(&DynamicAccount) -> bool,
	) -> Result<DynamicAccount, StoreError> {
		let display_name = changes
			.display_name
			.as_deref()
			.map(|raw| super::display_name::validate(raw).map_err(StoreError::Invalid))
			.transpose()?;
		let mut previous = None;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			if !authorize(target) {
				return Err(StoreError::NotFound(name.to_string()));
			}
			previous = Some(target.clone());
			if let Some(disabled) = changes.disabled {
				target.disabled = disabled;
			}
			if let Some(NewPassword { hash, scram }) = changes.password {
				target.password_hash = hash;
				target.scram = scram;
				target.rehashed = None;
				super::credential_reset::password_replaced(target);
			}
			if let Some(display_name) = display_name {
				target.display_name = display_name;
			}
			Ok(())
		})?;
		Ok(previous.expect("closure ran"))
	}

	/// Enable or disable a dynamic account (the SCIM `active` flag).
	/// Returns the previous state so callers can detect a no-op.
	pub fn set_disabled(&self, name: &str, disabled: bool) -> Result<bool, StoreError> {
		let mut previous = None;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			previous = Some(target.disabled);
			target.disabled = disabled;
			Ok(())
		})?;
		Ok(previous.expect("closure ran"))
	}

	/// Whether a dynamic account is administratively disabled.
	pub fn is_disabled(&self, name: &str) -> bool {
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.find(|account| account.name == name)
			.is_some_and(|account| account.disabled)
	}

	/// Look up a dynamic account by name (case-sensitive). `None` for
	/// static accounts and unknown names.
	pub fn dynamic(&self, name: &str) -> Option<DynamicAccount> {
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.find(|account| account.name == name)
			.cloned()
	}

	/// Snapshot every dynamic account (cloned). Used by SCIM's `List`
	/// and other read-only surfaces that need the full set without the
	/// lock.
	pub fn dynamic_accounts(&self) -> Vec<DynamicAccount> {
		self.dynamic.read().expect("store lock").clone()
	}
}

/// The held addresses that block a claim on `raw`, normalized: the address
/// itself and, when it carries a `+tag`, the address without it.
/// `alice+tag@host` delivers to `alice@host` unless it is held itself, so a
/// claim on the tagged form would divert the mail of whoever holds the base
/// address. Every check of a claim against an existing holder uses this, so
/// they cannot disagree about which claims collide.
pub(super) fn claim_forms(raw: &str) -> Vec<String> {
	let exact = normalize(raw);
	let mut forms = Vec::with_capacity(2);
	if let Some(base) = base_address(&exact) {
		forms.push(base);
	}
	forms.push(exact);
	forms
}

/// `local@domain` without a `+tag` in the local part, or `None` when the
/// address carries no tag. Delivery strips the same tag (see
/// `Directory::resolve`).
fn base_address(normalized: &str) -> Option<String> {
	let (local, domain) = normalized.rsplit_once('@')?;
	let cut = local.find('+').filter(|cut| *cut > 0)?;
	Some(format!("{}@{domain}", &local[..cut]))
}
