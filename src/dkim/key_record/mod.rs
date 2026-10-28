//! DNS key records (RFC 6376 section 3.6.1).
//!
//! A key record publishes the public key of one selector, the type of key
//! it holds in its `k=` tag, and the flags that constrain what the record
//! may authorize. The declared type decides which primitive verifies a
//! signature: a record that says `k=ed25519` never verifies an RSA
//! signature, and a record without a `k=` tag is an RSA record.

use base64::Engine;

use super::signature::Algorithm;

/// The key type a record declares in its `k=` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyType {
	/// `k=rsa`, and the default when the tag is absent (RFC 6376 section
	/// 3.6.1).
	Rsa,
	/// `k=ed25519` (RFC 8463 section 3).
	Ed25519,
}

/// A key record that can verify a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyRecord {
	/// The type the record declares in its `k=` tag.
	pub(crate) key_type: KeyType,
	/// The public key the `p=` tag carries.
	pub(crate) public_key: Vec<u8>,
	/// Whether the `t=` tag carries the "s" flag: the identity of the
	/// signature must name the signing domain exactly (RFC 6376 section
	/// 3.10).
	pub(crate) strict_identity: bool,
}

impl KeyRecord {
	/// Whether this record can verify a signature made with `algorithm`.
	/// The declared type decides the primitive, so an Ed25519 record never
	/// verifies an RSA signature and an RSA record never verifies an
	/// Ed25519 one.
	pub(crate) fn fits(&self, algorithm: Algorithm) -> bool {
		matches!(
			(self.key_type, algorithm),
			(KeyType::Rsa, Algorithm::RsaSha256) | (KeyType::Ed25519, Algorithm::Ed25519Sha256)
		)
	}

	/// Whether the identity of a signature is one this record authorizes
	/// (RFC 6376 section 3.10). Without the "s" flag the identity domain
	/// must be the signing domain or a subdomain of it; with the flag it
	/// must be the signing domain exactly. A signature without an identity
	/// names the signing domain itself.
	pub(crate) fn accepts_identity(&self, identity: Option<&str>, domain: &str) -> bool {
		let Some(identity) = identity else {
			return true;
		};
		let Some((_, identity_domain)) = identity.rsplit_once('@') else {
			return false;
		};
		let identity_domain = identity_domain.to_ascii_lowercase();
		if self.strict_identity {
			return identity_domain == domain;
		}
		identity_domain == domain
			|| identity_domain
				.strip_suffix(domain)
				.is_some_and(|prefix| prefix.ends_with('.'))
	}
}

/// The key record that verifies a signature, picked from the TXT answer of
/// a selector. `None` when no record can verify it: the answer holds no
/// usable record (malformed, revoked or without a key), or every usable
/// record declares a key type the signature does not use.
pub(crate) fn select(texts: &[String], algorithm: Algorithm) -> Option<KeyRecord> {
	texts
		.iter()
		.filter_map(|text| parse(text))
		.find(|record| record.fits(algorithm))
}

/// Parse one key record. `None` when the record cannot verify anything: no
/// `p=` tag, a revoked key (an empty `p=`), a `p=` that is not base64, or
/// a `k=` tag this verifier does not implement.
pub(crate) fn parse(text: &str) -> Option<KeyRecord> {
	let mut key_type = KeyType::Rsa;
	let mut public_key: Option<Vec<u8>> = None;
	let mut strict_identity = false;
	for tag in text.split(';') {
		let tag = tag.trim();
		let Some((name, value)) = tag.split_once('=') else {
			continue;
		};
		let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
		match name.trim() {
			"k" => {
				key_type = match value.as_str() {
					"rsa" => KeyType::Rsa,
					"ed25519" => KeyType::Ed25519,
					// An unknown key type is ignored, so the record cannot
					// verify anything.
					_ => return None,
				};
			}
			"p" => {
				if public_key.is_some() {
					continue;
				}
				if value.is_empty() {
					// An empty `p=` revokes the key (RFC 6376 section
					// 3.6.1).
					return None;
				}
				public_key = Some(
					base64::engine::general_purpose::STANDARD
						.decode(value)
						.ok()?,
				);
			}
			"t" => {
				strict_identity = value.split(':').any(|flag| flag == "s");
			}
			_ => {}
		}
	}
	Some(KeyRecord {
		key_type,
		public_key: public_key?,
		strict_identity,
	})
}

#[cfg(test)]
pub(crate) mod tests;
