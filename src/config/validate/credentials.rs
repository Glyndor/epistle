//! Static API credentials and account validation.

use super::*;

impl Config {
	pub(super) fn validate_api(&self) -> Result<(), ConfigError> {
		if let Some(hash) = self.api.as_ref().and_then(|api| api.token_hash.as_deref()) {
			// Accept both token-hash formats the runtime understands: the
			// `sha256:<64-hex>` form emitted by `mail token-hash` (the current
			// default), and a legacy argon2id PHC string.
			let sha256 = hash
				.strip_prefix("sha256:")
				.is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
			let argon2id = hash.starts_with("$argon2id$")
				&& argon2::password_hash::phc::PasswordHash::new(hash).is_ok();
			if !sha256 && !argon2id {
				return Err(ConfigError::Invalid(
					"[api] token_hash must be a `sha256:<hex>` (from `mail token-hash`) or argon2id PHC string".into(),
				));
			}
		}
		Ok(())
	}

	pub(super) fn validate_accounts(&self) -> Result<(), ConfigError> {
		let domains: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut names = HashSet::new();
		let mut addresses = HashSet::new();
		let mut catch_all_domains = HashSet::new();
		for account in &self.accounts {
			let name = &account.name;
			// The name becomes a directory under data_dir: keep it boring.
			if let Err(fault) = crate::util::account_rule::check(name) {
				return Err(ConfigError::Invalid(crate::util::account_rule::refusal(
					name, &fault,
				)));
			}
			if !names.insert(name.clone()) {
				return Err(ConfigError::Invalid(format!(
					"duplicate account name \"{name}\""
				)));
			}
			if account.addresses.is_empty() {
				return Err(ConfigError::Invalid(format!(
					"account \"{name}\" has no addresses"
				)));
			}
			if let Some(raw) = &account.display_name {
				crate::directory_store::display_name::validate(raw)
					.map_err(|why| ConfigError::Invalid(format!("account \"{name}\": {why}")))?;
			}
			if let Some(hash) = &account.password_hash {
				let argon2id = hash.starts_with("$argon2id$")
					&& argon2::password_hash::phc::PasswordHash::new(hash).is_ok();
				if !argon2id {
					return Err(ConfigError::Invalid(format!(
						"account \"{name}\": password_hash must be an argon2id PHC string"
					)));
				}
			}
			account.validate_forward().map_err(ConfigError::Invalid)?;
			for raw in &account.addresses {
				let address = crate::util::address_reason::parse(raw)
					.map_err(|why| ConfigError::Invalid(format!("account \"{name}\": {why}")))?;
				if !domains.contains(address.domain()) {
					return Err(ConfigError::Invalid(format!(
						"account \"{name}\": {}",
						crate::util::address_reason::not_handled(address.domain())
					)));
				}
				let key = crate::util::address::normalize(raw);
				if !addresses.insert(key.clone()) {
					let first = self
						.accounts
						.iter()
						.find(|other| other.addresses.contains(&key))
						.map_or(name.as_str(), |other| other.name.as_str());
					return Err(ConfigError::Invalid(format!(
						"address \"{key}\" belongs to both account \"{first}\" and account \"{name}\""
					)));
				}
			}
			for raw in &account.catch_all {
				let domain = raw.to_ascii_lowercase();
				if !domains.contains(&domain) {
					return Err(ConfigError::Invalid(format!(
						"account \"{name}\": catch_all domain \"{raw}\" is not a configured domain"
					)));
				}
				if !catch_all_domains.insert(domain) {
					return Err(ConfigError::Invalid(format!(
						"domain \"{raw}\" has more than one catch-all account"
					)));
				}
			}
		}
		// RFC 5321 §4.5.1: the server MUST accept mail addressed to
		// `postmaster` at every domain it serves. Without an explicit
		// `postmaster@<domain>` address or a per-domain catch-all, RCPT TO
		// for that address would resolve to `UnknownUser` and the server
		// would 5.1.1 the message — the MUST violation. We warn at validate
		// time so `config-check` and `serve` both surface the missing
		// address instead of leaving it for the first inbound bounce
		// report, but we do NOT reject the config: an upgrade that refuses
		// to start a previously-running server is a worse failure mode than
		// the RFC violation it was meant to fix, and operators have been
		// running without a configured `postmaster@` for a while now. The
		// runtime still rejects `postmaster@<domain>` at delivery time when
		// no address or catch-all exists; closing the MUST for real is a
		// follow-up that converts this warning into a hard error behind an
		// opt-in flag once we know how many deployments rely on the
		// permissive behaviour. Skipped when no accounts are configured: an
		// account-less server has nothing to deliver mail to regardless.
		// RFC 2142 lists `abuse@` as a SHOULD, not a MUST, so it is not
		// enforced here — when an operator adds it (explicit address or
		// catch-all), the existing resolution order accepts it.
		if !self.accounts.is_empty() {
			for domain in &self.domains {
				let domain_lc = domain.to_ascii_lowercase();
				let key = format!("postmaster@{domain_lc}");
				if addresses.contains(&key) || catch_all_domains.contains(&domain_lc) {
					continue;
				}
				tracing::warn!(
					domain = %domain,
					"domain \"{domain}\" has no `postmaster@<domain>` address and no catch-all; \
					 RFC 5321 §4.5.1 requires the server to accept mail to postmaster. \
					 Fix by adding a `postmaster@<domain>` address to an account, or by \
					 adding the domain to some account's `catch_all`."
				);
			}
		}
		Ok(())
	}
}
