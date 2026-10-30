//! ACME account key and JWS request signing (RFC 8555 §6.2, ES256).
//!
//! Every ACME request is a flattened JWS signed by the account key. This
//! module owns the P-256 key, derives its JWK, and produces signed requests;
//! the HTTP transport that carries them lives elsewhere.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

/// Errors from key handling or signing.
#[derive(Debug, thiserror::Error)]
pub enum JwsError {
	/// The OS CSPRNG refused to produce an ECDSA P-256 key pair. Should not
	/// happen on a healthy host; surfaces `ring::error::Unspecified`.
	#[error("key generation failed")]
	KeyGen,
	/// The supplied PKCS#8 bytes could not be parsed as an ECDSA P-256 key.
	#[error("invalid account key material")]
	InvalidKey,
	/// The signing input could not be produced (protected-header or flattened
	/// JWS serialization failed, or `ring` refused to sign).
	#[error("signing failed")]
	Signing,
}

/// An ACME account key (ECDSA P-256 / ES256).
pub struct AccountKey {
	key_pair: EcdsaKeyPair,
	rng: SystemRandom,
}

impl AccountKey {
	/// Generate a fresh account key, returning it and its PKCS#8 bytes (to
	/// persist and later restore with [`AccountKey::from_pkcs8`]).
	pub fn generate() -> Result<(Self, Vec<u8>), JwsError> {
		let rng = SystemRandom::new();
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
			.map_err(|_| JwsError::KeyGen)?;
		let key = Self::from_pkcs8(pkcs8.as_ref())?;
		Ok((key, pkcs8.as_ref().to_vec()))
	}

	/// Restore an account key from its PKCS#8 bytes.
	pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, JwsError> {
		let rng = SystemRandom::new();
		let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes, &rng)
			.map_err(|_| JwsError::InvalidKey)?;
		Ok(AccountKey { key_pair, rng })
	}

	/// The account key's public JWK (RFC 7517) for `newAccount` and thumbprints.
	pub fn jwk(&self) -> Value {
		// Uncompressed point: 0x04 || X(32) || Y(32).
		let point = self.key_pair.public_key().as_ref();
		let x = B64.encode(&point[1..33]);
		let y = B64.encode(&point[33..65]);
		json!({ "crv": "P-256", "kty": "EC", "x": x, "y": y })
	}

	/// The JWK SHA-256 thumbprint (RFC 7638), base64url. Built from the
	/// required members in lexicographic order with no whitespace.
	pub fn thumbprint(&self) -> String {
		let point = self.key_pair.public_key().as_ref();
		let x = B64.encode(&point[1..33]);
		let y = B64.encode(&point[33..65]);
		let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
		let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
		B64.encode(digest.as_ref())
	}

	/// The key authorization for a challenge `token` (RFC 8555 §8.1):
	/// `token "." base64url(thumbprint)`.
	pub fn key_authorization(&self, token: &str) -> String {
		format!("{token}.{}", self.thumbprint())
	}

	/// The DNS-01 TXT value for a challenge `token` (RFC 8555 §8.4):
	/// `base64url(sha256(key_authorization))`, published at
	/// `_acme-challenge.<domain>`.
	pub fn dns01_value(&self, token: &str) -> String {
		let key_authorization = self.key_authorization(token);
		let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
		B64.encode(digest.as_ref())
	}

	/// Build a flattened JWS for an ACME request to `url` with anti-replay
	/// `nonce`. A `key_id` (account URL) selects the `kid` header; without one
	/// the embedded `jwk` is used (for `newAccount`).
	pub fn sign(
		&self,
		url: &str,
		nonce: &str,
		payload: &[u8],
		key_id: Option<&str>,
	) -> Result<String, JwsError> {
		let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
		match key_id {
			Some(kid) => protected["kid"] = json!(kid),
			None => protected["jwk"] = self.jwk(),
		}
		let protected_b64 =
			B64.encode(serde_json::to_vec(&protected).map_err(|_| JwsError::Signing)?);
		let payload_b64 = B64.encode(payload);
		let signing_input = format!("{protected_b64}.{payload_b64}");
		let signature = self
			.key_pair
			.sign(&self.rng, signing_input.as_bytes())
			.map_err(|_| JwsError::Signing)?;
		let jws = json!({
			"protected": protected_b64,
			"payload": payload_b64,
			"signature": B64.encode(signature.as_ref()),
		});
		serde_json::to_string(&jws).map_err(|_| JwsError::Signing)
	}
}

#[cfg(test)]
mod tests;
