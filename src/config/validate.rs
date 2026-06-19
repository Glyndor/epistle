//! Semantic validation beyond what the type system enforces.

use std::collections::HashSet;

use super::{Config, ConfigError};

impl Config {
	/// Validate the configuration. Any violation is an error: the server
	/// refuses to start rather than run with a questionable setup.
	pub(super) fn validate(&self) -> Result<(), ConfigError> {
		validate_dns_name("hostname", &self.hostname)?;
		self.validate_data_dir()?;
		self.validate_domains()?;
		self.validate_accounts()?;
		self.validate_api()?;
		self.validate_listeners()?;
		self.validate_acme()?;
		self.validate_webhook()?;
		Ok(())
	}

	fn validate_webhook(&self) -> Result<(), ConfigError> {
		let Some(webhook) = &self.webhook else {
			return Ok(());
		};
		// Event payloads carry message metadata, so require TLS — except for a
		// loopback endpoint, which never leaves the host.
		let loopback = ["http://127.0.0.1", "http://[::1]", "http://localhost"]
			.iter()
			.any(|prefix| webhook.url.starts_with(prefix));
		if !webhook.url.starts_with("https://") && !loopback {
			return Err(ConfigError::Invalid(
				"[webhook] url must be https (or a loopback http endpoint)".into(),
			));
		}
		Ok(())
	}

	fn validate_acme(&self) -> Result<(), ConfigError> {
		let Some(acme) = &self.acme else {
			return Ok(());
		};
		if !acme.directory_url.starts_with("https://") {
			return Err(ConfigError::Invalid(
				"[acme] directory_url must be an https URL".into(),
			));
		}
		if acme.domains.is_empty() {
			return Err(ConfigError::Invalid(
				"[acme] requires at least one domain".into(),
			));
		}
		let configured: HashSet<String> = self
			.domains
			.iter()
			.map(|d| d.to_ascii_lowercase())
			.collect();
		for domain in &acme.domains {
			validate_dns_name("acme domain", domain)?;
			if !configured.contains(&domain.to_ascii_lowercase()) {
				return Err(ConfigError::Invalid(format!(
					"[acme] domain \"{domain}\" is not a configured domain"
				)));
			}
		}
		Ok(())
	}

	fn validate_api(&self) -> Result<(), ConfigError> {
		if let Some(api) = &self.api {
			// Accept both token-hash formats the runtime understands: the
			// `sha256:<64-hex>` form emitted by `mail token-hash` (the current
			// default), and a legacy argon2id PHC string.
			let sha256 = api
				.token_hash
				.strip_prefix("sha256:")
				.is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
			let argon2id = api.token_hash.starts_with("$argon2id$")
				&& argon2::password_hash::PasswordHash::new(&api.token_hash).is_ok();
			if !sha256 && !argon2id {
				return Err(ConfigError::Invalid(
					"[api] token_hash must be a `sha256:<hex>` (from `mail token-hash`) or argon2id PHC string".into(),
				));
			}
		}
		Ok(())
	}

	fn validate_accounts(&self) -> Result<(), ConfigError> {
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
			let safe_name = !name.is_empty()
				&& name.len() <= 64
				&& name
					.chars()
					.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
				&& !name.starts_with('-');
			if !safe_name {
				return Err(ConfigError::Invalid(format!(
					"account name \"{name}\" must be lowercase alphanumeric/hyphen"
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
			if let Some(hash) = &account.password_hash {
				let argon2id = hash.starts_with("$argon2id$")
					&& argon2::password_hash::PasswordHash::new(hash).is_ok();
				if !argon2id {
					return Err(ConfigError::Invalid(format!(
						"account \"{name}\": password_hash must be an argon2id PHC string"
					)));
				}
			}
			for raw in &account.addresses {
				let address = crate::smtp::address::Address::parse(raw).map_err(|_| {
					ConfigError::Invalid(format!("account \"{name}\": invalid address \"{raw}\""))
				})?;
				if !domains.contains(address.domain()) {
					return Err(ConfigError::Invalid(format!(
						"account \"{name}\": address \"{raw}\" is not in a configured domain"
					)));
				}
				if !addresses.insert(address.to_string().to_ascii_lowercase()) {
					return Err(ConfigError::Invalid(format!(
						"address \"{raw}\" is assigned to more than one account"
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
		Ok(())
	}

	fn validate_domains(&self) -> Result<(), ConfigError> {
		if !self.listeners.is_empty() && self.domains.is_empty() {
			return Err(ConfigError::Invalid(
				"at least one entry in \"domains\" is required when listeners are configured"
					.into(),
			));
		}
		let mut seen = HashSet::new();
		for domain in &self.domains {
			validate_dns_name("domain", domain)?;
			if !seen.insert(domain.to_ascii_lowercase()) {
				return Err(ConfigError::Invalid(format!(
					"duplicate domain \"{domain}\""
				)));
			}
		}
		for (alias, target) in &self.domain_aliases {
			validate_dns_name("domain alias", alias)?;
			let alias_lc = alias.to_ascii_lowercase();
			let target_lc = target.to_ascii_lowercase();
			if !seen.contains(&target_lc) {
				return Err(ConfigError::Invalid(format!(
					"domain alias \"{alias}\" targets \"{target}\", which is not a configured domain"
				)));
			}
			if seen.contains(&alias_lc) {
				return Err(ConfigError::Invalid(format!(
					"domain alias \"{alias}\" is also a configured domain"
				)));
			}
			if alias_lc == target_lc {
				return Err(ConfigError::Invalid(format!(
					"domain alias \"{alias}\" cannot target itself"
				)));
			}
		}
		Ok(())
	}

	fn validate_data_dir(&self) -> Result<(), ConfigError> {
		if self.data_dir.as_os_str().is_empty() {
			return Err(ConfigError::Invalid("data_dir must not be empty".into()));
		}
		if !self.data_dir.is_absolute() {
			return Err(ConfigError::Invalid(format!(
				"data_dir \"{}\" must be an absolute path",
				self.data_dir.display()
			)));
		}
		Ok(())
	}

	fn validate_listeners(&self) -> Result<(), ConfigError> {
		let mut seen = HashSet::new();
		for listener in &self.listeners {
			let addr = listener.socket_addr();
			if !seen.insert(addr) {
				return Err(ConfigError::Invalid(format!(
					"duplicate listener address {addr}"
				)));
			}
			if listener.kind == crate::config::ListenerKind::Submissions && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"submissions\" (implicit TLS) but no [tls] section is configured"
				)));
			}
			let needs_tls = matches!(
				listener.kind,
				crate::config::ListenerKind::Imaps | crate::config::ListenerKind::Imap
			);
			if needs_tls && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} requires a [tls] section (IMAP logins never cross plaintext)"
				)));
			}
			if listener.kind == crate::config::ListenerKind::Api && self.api.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"api\" but no [api] section is configured"
				)));
			}
		}
		Ok(())
	}
}

/// Validate a fully qualified DNS name; `field` names it in errors.
fn validate_dns_name(field: &str, name: &str) -> Result<(), ConfigError> {
	let name = name.trim();
	if name.is_empty() {
		return Err(ConfigError::Invalid(format!("{field} must not be empty")));
	}
	if !name.contains('.') {
		return Err(ConfigError::Invalid(format!(
			"{field} \"{name}\" must be fully qualified (contain a dot)"
		)));
	}
	if name.len() > 253
		|| name
			.split('.')
			.any(|label| label.is_empty() || label.len() > 63)
	{
		return Err(ConfigError::Invalid(format!(
			"{field} \"{name}\" is not a valid DNS name"
		)));
	}
	let valid_chars = name
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
	if !valid_chars {
		return Err(ConfigError::Invalid(format!(
			"{field} \"{name}\" contains invalid characters"
		)));
	}
	Ok(())
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "validate_tests_b.rs"]
mod tests_b;
