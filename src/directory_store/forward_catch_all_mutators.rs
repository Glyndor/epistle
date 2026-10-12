//! In-place mutators for `account forward` and `account catch-all`.
//!
//! Lives in a sibling so `mutators.rs` stays under the per-file code-line
//! budget. The methods here all run through
//! [`AccountStore::mutate_store`] so the cross-process `flock` and the
//! "re-read before mutate" check the rest of the dynamic mutators apply
//! are inherited for free.
//!
//! A forward target may be any external address: it is the operator's
//! choice where copies go, but it cannot be one of the account's own
//! addresses (the loop back would re-deliver the same message inside
//! the same mailbox and shadow every other forward target). A catch-all
//! entry must name a configured domain no other account catches, the
//! same rule the config loader applies to a static `catch_all`.

use super::{AccountStore, DynamicAccount, StoreError};

impl AccountStore {
	/// Append `target` to the dynamic account's forward list. Refuses:
	///
	/// * `target` that fails `Address::parse` (otherwise the row sits on
	///   disk forever as junk);
	/// * `target` equal to one of the account's own addresses (the
	///   forward would loop back onto the same mailbox and shadow every
	///   other recipient);
	/// * a duplicate target (the directory already has it, accepting
	///   silently would mint a second delivery for every message).
	pub fn add_forward(&self, name: &str, target: &str) -> Result<(), StoreError> {
		self.mutate_store(|state| {
			let target_owned = target.to_string();
			let target_parsed =
				crate::util::address_reason::parse(&target_owned).map_err(StoreError::Invalid)?;
			let account = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			let target_lower = target_owned.to_ascii_lowercase();
			if account
				.addresses
				.iter()
				.any(|owned| owned.eq_ignore_ascii_case(&target_owned))
			{
				return Err(StoreError::Invalid(format!(
					"cannot forward {name} to its own address {target}"
				)));
			}
			if account
				.forward
				.iter()
				.any(|existing| existing.eq_ignore_ascii_case(&target_owned))
			{
				return Err(StoreError::Duplicate(format!("{}/{}", name, target_lower)));
			}
			// Touch the parsed form so the parse-validated path is the
			// same one the builder's forward chain uses at delivery.
			let _ = target_parsed.local_part();
			account.forward.push(target_owned);
			Ok(())
		})?;
		Ok(())
	}

	/// Drop `target` from the dynamic account's forward list. The target
	/// must currently be on the list; an unknown target is `Invalid`, not
	/// a silent skip (silent skips let a typo sit, doing nothing).
	pub fn remove_forward(&self, name: &str, target: &str) -> Result<(), StoreError> {
		let target_owned = target.to_string();
		self.mutate_store(|state| {
			let account = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			let is_target = |existing: &String| existing.eq_ignore_ascii_case(&target_owned);
			if !account.forward.iter().any(is_target) {
				return Err(StoreError::Invalid(format!(
					"{target} is not in {name}'s forward list"
				)));
			}
			account.forward.retain(|existing| !is_target(existing));
			Ok(())
		})?;
		Ok(())
	}

	/// Append `domain` to the dynamic account's catch-all list, the way the
	/// config loader accepts a static `catch_all`. Refuses:
	///
	/// * a domain that is not in `self.domains`. That covers a domain alias
	///   too: delivery resolves an alias to its target domain before it
	///   looks a catch-all up, so one set on the alias is never consulted;
	/// * a domain another account (static or dynamic) already catches. The
	///   directory keeps one catch-all account per domain, so a second one
	///   would silently take the domain from the first;
	/// * a duplicate domain.
	///
	/// The domain is stored lowercase, as the directory compares it.
	pub fn add_catch_all(&self, name: &str, domain: &str) -> Result<(), StoreError> {
		let domain_lower = domain.trim().to_ascii_lowercase();
		if let Some(target) = self.domain_aliases.get(&domain_lower) {
			return Err(StoreError::Invalid(format!(
				"{domain} is an alias of {target}; set the catch-all on {target}"
			)));
		}
		if !self
			.domains
			.iter()
			.any(|configured| configured.eq_ignore_ascii_case(&domain_lower))
		{
			return Err(StoreError::Invalid(
				crate::util::address_reason::not_handled(&domain_lower),
			));
		}
		let catches = |list: &[String]| list.iter().any(|d| d.eq_ignore_ascii_case(&domain_lower));
		if let Some(owner) = self
			.static_accounts
			.iter()
			.find(|account| catches(&account.catch_all))
		{
			return Err(StoreError::Invalid(format!(
				"{domain_lower} already has a catch-all account: {}",
				owner.name
			)));
		}
		self.mutate_store(|state| {
			if let Some(owner) = state
				.accounts
				.iter()
				.find(|account| account.name != name && catches(&account.catch_all))
			{
				return Err(StoreError::Invalid(format!(
					"{domain_lower} already has a catch-all account: {}",
					owner.name
				)));
			}
			let account = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			if catches(&account.catch_all) {
				return Err(StoreError::Duplicate(format!("{name}/{domain_lower}")));
			}
			account.catch_all.push(domain_lower.clone());
			Ok(())
		})?;
		Ok(())
	}

	/// Drop `domain` from the dynamic account's catch-all list. Unknown
	/// domain is `Invalid`, not a silent skip.
	pub fn remove_catch_all(&self, name: &str, domain: &str) -> Result<(), StoreError> {
		let domain_owned = domain.to_string();
		self.mutate_store(|state| {
			let account = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			let is_target = |existing: &String| existing.eq_ignore_ascii_case(&domain_owned);
			if !account.catch_all.iter().any(is_target) {
				return Err(StoreError::Invalid(format!(
					"{domain} is not in {name}'s catch-all list"
				)));
			}
			account.catch_all.retain(|existing| !is_target(existing));
			Ok(())
		})?;
		Ok(())
	}

	/// The forward targets currently set on `name`, or an empty vec
	/// when the account is unknown. A read, not a mutator: the CLI
	/// `account forward list` needs this without taking the file lock.
	pub fn forwards(&self, name: &str) -> Vec<String> {
		let dynamic = self.dynamic.read().expect("store lock");
		dynamic
			.iter()
			.find(|account| account.name == name)
			.map(|account| account.forward.clone())
			.unwrap_or_default()
	}

	/// The catch-all domains currently set on `name`, or an empty vec
	/// when the account is unknown.
	pub fn catch_alls(&self, name: &str) -> Vec<String> {
		let dynamic = self.dynamic.read().expect("store lock");
		dynamic
			.iter()
			.find(|account| account.name == name)
			.map(|account| account.catch_all.clone())
			.unwrap_or_default()
	}

	/// Borrow the dynamic account record by name; the CLI uses this for
	/// the `account show` JSON output and for the `2fa` tests that
	/// need the stored secret without round-tripping through disk.
	pub fn dynamic_account(&self, name: &str) -> Option<DynamicAccount> {
		let dynamic = self.dynamic.read().expect("store lock");
		dynamic.iter().find(|account| account.name == name).cloned()
	}
}
