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

/// Whether `published` is a key record that can verify the signatures the
/// record `expected` would: the same key of the same type, and no `h=`, `s=`,
/// repeated tag or revocation that stops it (see [`parse`]). Comparing the
/// `p=` text alone would accept a record that no verifier can use.
pub(crate) fn same_usable_key(published: &str, expected: &str) -> bool {
	match (parse(published), parse(expected)) {
		(Some(a), Some(b)) => a.key_type == b.key_type && a.public_key == b.public_key,
		_ => false,
	}
}

/// The most tags a key record may carry before it is refused.
const MAX_TAGS: usize = 64;

/// Parse one key record. `None` when the record cannot verify anything: no
/// `p=` tag, a revoked key (an empty `p=`), a `p=` that is not base64, or
/// a `k=` tag this verifier does not implement.
pub(crate) fn parse(text: &str) -> Option<KeyRecord> {
	let mut key_type = KeyType::Rsa;
	let mut public_key: Option<Vec<u8>> = None;
	let mut strict_identity = false;
	let mut seen: Vec<&str> = Vec::new();
	for tag in text.split(';') {
		let tag = tag.trim();
		let Some((name, value)) = tag.split_once('=') else {
			continue;
		};
		let name = name.trim();
		// A tag name may appear once: a list that repeats one is invalid
		// as a whole, so a later `p=`, `k=` or `t=` cannot hide or replace
		// an earlier one (RFC 6376 section 3.2).
		if seen.contains(&name) {
			return None;
		}
		// A key record carries about six tags. The cap keeps the search
		// above from growing with the size of a hostile TXT answer.
		if seen.len() >= MAX_TAGS {
			return None;
		}
		seen.push(name);
		let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
		match name {
			// The version, when present, is the one this verifier speaks.
			"v" if value != "DKIM1" => return None,
			// The hash algorithms the key is limited to: this verifier
			// signs and checks with SHA-256 only.
			"h" if !value.split(':').any(|hash| hash == "sha256") => return None,
			// The services the key is limited to: it has to cover email.
			"s" if !value
				.split(':')
				.any(|service| service == "email" || service == "*") =>
			{
				return None;
			}
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
	let public_key = public_key?;
	// The material has to be the kind of key the record declares: an
	// Ed25519 key is 32 raw bytes (RFC 8463 section 4), an RSA key a DER
	// structure much longer than that.
	let fits_type = match key_type {
		KeyType::Ed25519 => public_key.len() == 32,
		KeyType::Rsa => public_key.len() > 32 && public_key.first() == Some(&0x30),
	};
	fits_type.then_some(KeyRecord {
		key_type,
		public_key,
		strict_identity,
	})
}

#[cfg(test)]
pub(crate) mod tests;
