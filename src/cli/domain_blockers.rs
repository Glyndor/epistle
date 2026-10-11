//! `epistle domain`: refuse removal while any account (static or
//! dynamic), alias, masked address or `domain_aliases` entry still uses
//! the domain. Lists every offender so the operator knows what to drop
//! first.

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
	// Aliases (their address, members and senders).
	for alias in &config.alias {
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

pub fn address_domain_matches(address: &str, domain: &str) -> bool {
	Address::parse(address)
		.map(|parsed| parsed.domain().eq_ignore_ascii_case(domain))
		.unwrap_or(false)
}
