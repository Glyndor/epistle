//! The public key an ARC header is verified against.
//!
//! RFC 8617 reuses DKIM's key record, but the algorithm the header declares
//! has to govern both the primitive and the shape of the key: a header that
//! says `a=ed25519-sha256` needs an Ed25519 key, and a header that says
//! `a=rsa-sha256` needs an RSA key. A record that publishes one kind of key
//! for a header that declares the other is refused, never read as whichever
//! primitive the verifier happened to use.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{ED25519, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, UnparsedPublicKey};

use crate::dkim::Algorithm;

/// The length of an Ed25519 public key, in bytes (RFC 8463 section 4).
const ED25519_KEY_LEN: usize = 32;

/// The smallest RSA modulus this verifier accepts, in bits. RFC 6376 section
/// 3.6.1 asks for at least 1024 bits, and a smaller modulus cannot carry a
/// signature this verifier would accept. Only a verifier uses a key this
/// small: every key epistle makes or publishes is bigger.
const MIN_RSA_BITS: usize = 1024;

/// The largest RSA modulus this verifier accepts, in bits.
const MAX_RSA_BITS: usize = 8192;

/// The key type a DNS key record declares with its `k=` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyType {
	/// `k=rsa`, and also the type of a record with no `k=` tag: RFC 6376
	/// section 3.6.1 makes `rsa` the default.
	Rsa,
	/// `k=ed25519` (RFC 8463 section 4).
	Ed25519,
}

/// A key record as the DNS publishes it: the key type it declares and the
/// key bytes it carries.
pub(crate) struct KeyRecord {
	key_type: KeyType,
	key: Vec<u8>,
}

/// Why a published key cannot be used with the declared algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyError {
	/// No string of the answer publishes a key.
	Missing,
	/// The record declares a key type this verifier does not know: RFC 6376
	/// section 3.6.1 tells it to ignore such a key.
	UnknownType,
	/// The record declares a key type the declared algorithm does not use.
	TypeMismatch,
	/// The key is not in the shape the declared algorithm needs.
	Unusable,
}

/// The key a record publishes, ready to verify with.
pub(crate) enum VerificationKey {
	/// The bytes of an Ed25519 public key.
	Ed25519(Vec<u8>),
	/// A PKCS#1 `RSAPublicKey` body: the RSA key without the
	/// SubjectPublicKeyInfo envelope that wraps it in a record.
	Rsa(Vec<u8>),
}

impl KeyRecord {
	/// The record the DNS publishes for the key: the first string with a
	/// `p=` tag, which RFC 6376 section 3.6.1 tells the verifier to use.
	/// The key type is read from that same string.
	pub(crate) fn first(texts: &[String]) -> Result<Self, KeyError> {
		for text in texts {
			match Self::parse(text)? {
				Some(record) => return Ok(record),
				// A string with no `p=` tag is not a key record.
				None => continue,
			}
		}
		Err(KeyError::Missing)
	}

	/// Read one DNS string as a key record. `Ok(None)` when the string
	/// publishes no key. `Err` when it publishes one that cannot be used: a
	/// key type this verifier does not know, which RFC 6376 section 3.6.1
	/// tells it to ignore, or a key that is not base64.
	fn parse(text: &str) -> Result<Option<Self>, KeyError> {
		let mut key_type = KeyType::Rsa;
		let mut unknown_type = false;
		let mut key = None;
		for tag in text.split(';') {
			let tag = tag.trim();
			let Some((name, value)) = tag.split_once('=') else {
				continue;
			};
			let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
			match name.trim().to_ascii_lowercase().as_str() {
				"k" => {
					key_type = match value.to_ascii_lowercase().as_str() {
						"rsa" => KeyType::Rsa,
						"ed25519" => KeyType::Ed25519,
						_ => {
							unknown_type = true;
							KeyType::Rsa
						}
					};
				}
				"p" => key = Some(value),
				_ => {}
			}
		}
		let Some(value) = key else {
			return Ok(None);
		};
		if unknown_type {
			return Err(KeyError::UnknownType);
		}
		let key = BASE64.decode(value).map_err(|_| KeyError::Unusable)?;
		Ok(Some(Self { key_type, key }))
	}

	/// The key to verify `algorithm` with, in the shape that primitive
	/// expects, or why this record cannot be used with it.
	pub(crate) fn verification_key(
		&self,
		algorithm: Algorithm,
	) -> Result<VerificationKey, KeyError> {
		match (algorithm, self.key_type) {
			(Algorithm::Ed25519Sha256, KeyType::Ed25519) => {
				if self.key.len() != ED25519_KEY_LEN {
					return Err(KeyError::Unusable);
				}
				Ok(VerificationKey::Ed25519(self.key.clone()))
			}
			(Algorithm::RsaSha256, KeyType::Rsa) => {
				// A record carries the SubjectPublicKeyInfo (RFC 6376
				// section 3.6.1) and ring verifies against the
				// `RSAPublicKey` inside it. A record with the bare key is
				// used as it is.
				let pkcs1 =
					crate::dkim::rsa_public_key_from_spki(&self.key).unwrap_or(self.key.as_slice());
				let bits = crate::dkim::rsa_modulus_bits(pkcs1).ok_or(KeyError::Unusable)?;
				if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
					return Err(KeyError::Unusable);
				}
				Ok(VerificationKey::Rsa(pkcs1.to_vec()))
			}
			// The record publishes a key of the other type.
			_ => Err(KeyError::TypeMismatch),
		}
	}
}

impl VerificationKey {
	/// Whether `signature` is a valid signature of `signed` under this key.
	/// `signed` are the bytes the algorithm covers, which the caller asks
	/// the algorithm for.
	pub(crate) fn verify(&self, signed: &[u8], signature: &[u8]) -> bool {
		match self {
			VerificationKey::Ed25519(key) => UnparsedPublicKey::new(&ED25519, key)
				.verify(signed, signature)
				.is_ok(),
			VerificationKey::Rsa(key) => {
				UnparsedPublicKey::new(&RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, key)
					.verify(signed, signature)
					.is_ok()
			}
		}
	}
}
