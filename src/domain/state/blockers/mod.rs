//! Refuse to remove a hosted domain while any account (static or
//! dynamic), alias, masked address or domain alias still uses it, or the
//! configuration file names it where only the operator can change it
//! (`[acme] domains`, a `[[tenant]]`). Lists every offender so the operator
//! knows what to drop first. `epistle domain remove` and
//! `DELETE /api/v1/domains/{domain}` refuse with the same list.

use crate::config::Config;
use crate::smtp::address::Address;

/// Walk every account (static `[accounts]` plus `<data_dir>/accounts.toml`),
/// every `[alias]` and its members and senders, every `domain_aliases`
/// entry and every masked address on disk. If any of those still uses
/// the domain, returns the user-facing message listing each offender
/// by category.
pub fn removal_blockers(config: &Config, domain: &str) -> Result<(), String> {
	let mut offenders: Vec<String> = Vec::new();
	// Static accounts.
	for account in &config.accounts {
		for address in &account.addresses {
			if address_domain_matches(address, domain) {
				offenders.push(format!("account {} uses {address}", account.name));
			}
		}
	}
	// Aliases (their address, members and senders), as the alias state file
	// holds them now: a write that was made after this configuration was
	// loaded is a reason too.
	for alias in &crate::aliases::current(config) {
		if address_domain_matches(&alias.address, domain) {
			offenders.push(format!("alias {} uses the domain", alias.address));
		}
		for member in &alias.members {
			if address_domain_matches(member, domain) {
				offenders.push(format!("alias {} has member {member}", alias.address));
			}
		}
		for sender in &alias.senders {
			if address_domain_matches(sender, domain) {
				offenders.push(format!("alias {} allows sender {sender}", alias.address));
			}
		}
	}
	// domain_aliases map.
	for (alias, target) in &config.domain_aliases {
		if alias.eq_ignore_ascii_case(domain) {
			offenders.push(format!("domain_aliases has {alias} -> {target}"));
		}
		if target.eq_ignore_ascii_case(domain) {
			offenders.push(format!("domain_aliases maps {alias} to {domain}"));
		}
	}
	// What only an edit of the configuration file can change.
	if let Some(acme) = &config.acme
		&& acme
			.domains
			.iter()
			.any(|name| name.eq_ignore_ascii_case(domain))
	{
		offenders.push("the configuration file lists it in [acme] domains".to_string());
	}
	for tenant in &config.tenants {
		if tenant
			.domains
			.iter()
			.any(|name| name.eq_ignore_ascii_case(domain))
		{
			let name = tenant.name.as_deref().unwrap_or("without a name");
			offenders.push(format!("the configuration file's tenant {name} lists it"));
		}
	}
	// Masked addresses (a JSON-backed store on disk).
	let masked_path = config.data_dir.join("masked.json");
	if let Ok(text) = std::fs::read_to_string(&masked_path)
		&& let Ok(file) = serde_json::from_str::<serde_json::Value>(&text)
		&& let Some(addresses) = file.get("addresses").and_then(|v| v.as_object())
	{
		for (key, value) in addresses {
			if address_domain_matches(key, domain) {
				let owner = value.get("account").and_then(|v| v.as_str()).unwrap_or("?");
				offenders.push(format!("masked address {key} (account {owner})"));
			}
		}
	}
	// Dynamic accounts (data_dir/accounts.toml).
	let accounts_path = config.data_dir.join("accounts.toml");
	if let Ok(text) = std::fs::read_to_string(&accounts_path)
		&& let Ok(file) = toml::from_str::<toml::Value>(&text)
		&& let Some(accounts) = file.get("accounts").and_then(|v| v.as_array())
	{
		for account in accounts {
			let name = account.get("name").and_then(|v| v.as_str()).unwrap_or("?");
			if let Some(addresses) = account.get("addresses").and_then(|v| v.as_array()) {
				for address in addresses {
					if let Some(address) = address.as_str()
						&& address_domain_matches(address, domain)
					{
						offenders.push(format!("dynamic account {name} uses {address}"));
					}
				}
			}
		}
	}
	if offenders.is_empty() {
		Ok(())
	} else {
		offenders.sort();
		offenders.dedup();
		Err(format!(
			"domain {domain} is still in use: {}",
			offenders.join(", ")
		))
	}
}

/// Whether `address` parses and is in `domain`, without regard to ASCII case.
pub fn address_domain_matches(address: &str, domain: &str) -> bool {
	Address::parse(address)
		.map(|parsed| parsed.domain().eq_ignore_ascii_case(domain))
		.unwrap_or(false)
}
