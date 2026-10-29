//! DKIM half of the `dns` check: which key signs, and does the published
//! TXT record carry its public key?

use std::path::PathBuf;

use super::report::{Item, Level};
use crate::config::Config;
use crate::dkim::Signer;

/// A key the server signs with and the public key DNS should publish for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SigningKey {
	pub(super) selector: String,
	/// The `p=` value of the TXT record this key's public half produces.
	pub(super) public: String,
	/// The key file it was read from.
	pub(super) file: PathBuf,
}

/// A signing key with the domain it signs for: `None` for the `[dkim]`
/// default, which signs every domain without a `[[dkim.domain]]` override,
/// and the lowercase domain for an override, which signs only that domain.
pub(super) struct PerDomainSigningKey {
	pub(super) key: SigningKey,
	pub(super) domain: Option<String>,
}

/// The keys in use: the active Ed25519 key as the server resolves it
/// ([`crate::dkim::rotate::active_ed25519`]: an unreadable rotation state
/// is an error unless its last good copy stands in, see [`state_item`]),
/// plus the RSA key in service ([`crate::dkim::rotate::active_rsa`]) when
/// the server dual-signs, then each override's keys. Empty without a
/// `[dkim]` section.
pub(super) fn signing_keys(config: &Config) -> Result<Vec<PerDomainSigningKey>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let mut out = Vec::new();
	let active = crate::dkim::rotate::active_ed25519(dkim, &config.data_dir)
		.map_err(|error| error.to_string())?;
	let (selector, file) = (active.selector.clone(), active.key_file.clone());
	let signer = Signer::load(&selector, &file).map_err(|error| error.to_string())?;
	out.push(PerDomainSigningKey {
		key: SigningKey {
			selector,
			public: public_value(&signer.dns_record_value()),
			file,
		},
		domain: None,
	});
	let rsa = crate::dkim::rotate::active_rsa(dkim, &config.data_dir)
		.map_err(|error| error.to_string())?;
	if let Some(rsa) = rsa {
		let record =
			crate::dkim::rsa_record_value(&rsa.key_file).map_err(|error| error.to_string())?;
		out.push(PerDomainSigningKey {
			key: SigningKey {
				selector: rsa.selector,
				public: public_value(&record),
				file: rsa.key_file,
			},
			domain: None,
		});
	}
	// Per-domain overrides are checked alongside the default so a
	// single key_list drives every domain's check; the lookup then
	// skips the default for a domain that has its own override.
	for entry in &dkim.domain {
		let signer =
			Signer::load(&entry.selector, &entry.key_file).map_err(|error| error.to_string())?;
		out.push(PerDomainSigningKey {
			key: SigningKey {
				selector: entry.selector.clone(),
				public: public_value(&signer.dns_record_value()),
				file: entry.key_file.clone(),
			},
			domain: Some(entry.name.to_ascii_lowercase()),
		});
		if let (Some(rsa_selector), Some(rsa_key_file)) = (&entry.rsa_selector, &entry.rsa_key_file)
		{
			let record =
				crate::dkim::rsa_record_value(rsa_key_file).map_err(|error| error.to_string())?;
			out.push(PerDomainSigningKey {
				key: SigningKey {
					selector: rsa_selector.clone(),
					public: public_value(&record),
					file: rsa_key_file.clone(),
				},
				domain: Some(entry.name.to_ascii_lowercase()),
			});
		}
	}
	Ok(out)
}

/// The `p=` value of a DKIM TXT record, whitespace removed (long values are
/// split across strings and joined by some resolvers with spaces).
pub(super) fn public_value(record: &str) -> String {
	record
		.split(';')
		.filter_map(|tag| tag.trim().strip_prefix("p="))
		.next()
		.map(|value| value.split_whitespace().collect())
		.unwrap_or_default()
}

/// Compare what DNS publishes at `<selector>._domainkey.<domain>` with the
/// key the server signs with. `published` is every TXT string found there; a
/// name with no DKIM record is the plain DNS check's finding, not this one's.
pub(super) fn compare(key: &SigningKey, domain: &str, published: &[String]) -> Option<Item> {
	let record = published.iter().find(|text| {
		text.trim_start()
			.to_ascii_uppercase()
			.starts_with("V=DKIM1")
	})?;
	let name = format!("DKIM key {} {domain}", key.selector);
	if public_value(record) == key.public {
		return Some(Item::new(
			name,
			Level::Ok,
			"published key matches the signing key",
		));
	}
	Some(Item::new(
		name,
		Level::Fail,
		format!(
			"published p= does not match the signing key {}; update the TXT record",
			key.file.display()
		),
	))
}

/// A warning when the rotation state cannot be read and the server signs
/// with its last good copy instead: mail is still signed, but rotation
/// stays stopped until the operator restores the file.
pub(super) fn state_item(config: &Config) -> Option<Item> {
	use crate::dkim::rotate::{STATE_BACKUP_FILE, STATE_FILE, state_fallback};
	config.dkim.as_ref()?;
	let error = state_fallback(&config.data_dir)?;
	Some(Item::new(
		"DKIM rotation state",
		Level::Warn,
		format!(
			"{error}; signing with the last good state in {STATE_BACKUP_FILE}, and rotation is stopped until {STATE_FILE} is restored from it"
		),
	))
}

#[cfg(test)]
mod tests;
