//! Two signing owners that publish the same public key.
//!
//! The configuration check compares key file names. This one opens the files:
//! two paths that reach one key (a link, a copy) or two copies of one key
//! under different names are the same key to a receiver, and a leak of it
//! signs as every domain that uses it. The owners are the `[dkim]` default
//! (the key in service, so a rotated key counts, not the configured file it
//! replaced) and every `[[dkim.domain]]` entry. A key that does not load is
//! skipped here: the signer reports that when it loads it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::Signer;
use super::rotate::{active_ed25519, active_rsa};
use crate::config::Config;

/// One key in use and who it signs for.
struct Use {
	owner: String,
	file: PathBuf,
}

/// The `p=` value of a DKIM record, whitespace removed.
fn public_part(record: &str) -> Option<String> {
	record
		.split(';')
		.find_map(|tag| tag.trim().strip_prefix("p="))
		.map(|value| value.split_whitespace().collect())
}

/// The sharing messages, one per public key that more than one owner uses;
/// empty when every owner has its own. `Err` only when the rotation state
/// that says which default key is in service cannot be read.
pub fn shared_public_keys(config: &Config) -> Result<Vec<String>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let default_owner = || "[dkim] (the key every domain without its own key signs with)";
	// Keyed by algorithm and public key, so an ed25519 key never matches
	// an RSA one.
	let mut by_key: BTreeMap<(&'static str, String), Vec<Use>> = BTreeMap::new();
	let mut add =
		|algorithm: &'static str, public: Option<String>, owner: String, file: PathBuf| {
			if let Some(public) = public {
				by_key
					.entry((algorithm, public))
					.or_default()
					.push(Use { owner, file });
			}
		};
	let ed = |selector: &str, file: &std::path::Path| {
		Signer::load(selector, file)
			.ok()
			.and_then(|signer| public_part(&signer.dns_record_value()))
	};
	let rsa = |file: &std::path::Path| {
		super::rsa_record_value(file)
			.ok()
			.and_then(|record| public_part(&record))
	};
	let active = active_ed25519(dkim, &config.data_dir).map_err(|error| error.to_string())?;
	add(
		"ed25519",
		ed(&active.selector, &active.key_file),
		default_owner().to_string(),
		active.key_file,
	);
	if let Some(key) = active_rsa(dkim, &config.data_dir).map_err(|error| error.to_string())? {
		add(
			"rsa",
			rsa(&key.key_file),
			default_owner().to_string(),
			key.key_file,
		);
	}
	for entry in &dkim.domain {
		let owner = format!(
			"[dkim.domain] name = \"{}\"",
			entry.name.to_ascii_lowercase()
		);
		add(
			"ed25519",
			ed(&entry.selector, &entry.key_file),
			owner.clone(),
			entry.key_file.clone(),
		);
		if let Some(file) = &entry.rsa_key_file {
			add("rsa", rsa(file), owner, file.clone());
		}
	}
	Ok(by_key
		.into_iter()
		.filter(|(_, uses)| uses.len() > 1)
		.map(|((algorithm, _), uses)| {
			let list: Vec<String> = uses
				.iter()
				.map(|u| format!("{} ({})", u.owner, u.file.display()))
				.collect();
			format!(
				"{} publish the same {algorithm} public key; every hosted domain needs a key of its own (`epistle dkim split`, or `epistle dkim-keygen` for one domain)",
				list.join(" and ")
			)
		})
		.collect())
}

#[cfg(test)]
mod tests;
