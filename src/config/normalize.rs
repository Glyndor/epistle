//! The mail addresses and domains of `mail.toml` in their stored form.
//!
//! The file is the operator's and is never rewritten here. What is read from
//! it is lowercased in memory (see [`crate::util::address`]) before it is
//! validated, so a static account, alias or domain is compared, routed and
//! listed exactly like one created through the CLI or the API. Each entry
//! that was not already lowercase is recorded in [`Config::mixed_case`] for
//! `config-check` to name.

use super::Config;
use crate::util::address::normalize;

impl Config {
	/// Normalize the static addresses and domains in place and describe
	/// every entry that changed.
	pub(super) fn normalize_identifiers(&mut self) -> Vec<String> {
		let mut changed = Vec::new();
		for domain in &mut self.domains {
			let stored = config_domain(domain);
			note(&mut changed, "domains: ", domain, stored);
		}
		let mut aliases: Vec<(String, String)> = self.domain_aliases.drain().collect();
		aliases.sort();
		for (alias, target) in aliases {
			let (alias_stored, target_stored) = (config_domain(&alias), config_domain(&target));
			if alias_stored != alias || target_stored != target {
				changed.push(format!(
					"domain_aliases: \"{alias}\" = \"{target}\" (used as \"{alias_stored}\" = \"{target_stored}\")"
				));
			}
			self.domain_aliases.insert(alias_stored, target_stored);
		}
		for account in &mut self.accounts {
			let owner = format!("account \"{}\": ", account.name);
			for address in &mut account.addresses {
				note(
					&mut changed,
					&format!("{owner}address "),
					address,
					normalize(address),
				);
			}
			for target in &mut account.forward {
				note(
					&mut changed,
					&format!("{owner}forward "),
					target,
					normalize(target),
				);
			}
			for domain in &mut account.catch_all {
				let stored = config_domain(domain);
				note(&mut changed, &format!("{owner}catch_all "), domain, stored);
			}
		}
		for alias in &mut self.alias {
			let stored = normalize(&alias.address);
			note(&mut changed, "alias ", &mut alias.address, stored);
			let owner = format!("alias \"{}\": ", alias.address);
			for member in &mut alias.members {
				note(
					&mut changed,
					&format!("{owner}member "),
					member,
					normalize(member),
				);
			}
			for sender in &mut alias.senders {
				note(
					&mut changed,
					&format!("{owner}sender "),
					sender,
					normalize(sender),
				);
			}
		}
		changed
	}
}

/// A configured domain in its stored form. Only an ASCII domain is
/// lowercased here: a U-label is left as written so the validator still
/// refuses it with the A-label the operator should write instead.
fn config_domain(raw: &str) -> String {
	if raw.is_ascii() {
		raw.trim().to_ascii_lowercase()
	} else {
		raw.to_string()
	}
}

/// Replace `value` with `stored`, recording the entry when they differ.
fn note(changed: &mut Vec<String>, label: &str, value: &mut String, stored: String) {
	if *value != stored {
		changed.push(format!("{label}\"{value}\" (used as \"{stored}\")"));
		*value = stored;
	}
}

#[cfg(test)]
#[path = "normalize_tests.rs"]
mod tests;
