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

/// The keys in use: the active Ed25519 key as the server resolves it
/// ([`crate::dkim::rotate::active_ed25519`], an unreadable rotation state is
/// an error), plus the RSA key when configured. Empty without a `[dkim]`
/// section.
pub(super) fn signing_keys(config: &Config) -> Result<Vec<SigningKey>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let active = crate::dkim::rotate::active_ed25519(dkim, &config.data_dir)
		.map_err(|error| error.to_string())?;
	let (selector, file) = (active.selector, active.key_file);
	let mut signer = Signer::load(&selector, &file).map_err(|error| error.to_string())?;
	let mut keys = vec![SigningKey {
		selector,
		public: public_value(&signer.dns_record_value()),
		file,
	}];
	if let (Some(selector), Some(file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
		signer = signer
			.with_rsa(selector, file)
			.map_err(|error| error.to_string())?;
		let record = signer.rsa_dns_record_value().unwrap_or_default();
		keys.push(SigningKey {
			selector: selector.clone(),
			public: public_value(&record),
			file: file.clone(),
		});
	}
	Ok(keys)
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
