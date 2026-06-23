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
	#[error("key generation failed")]
	KeyGen,
	#[error("invalid account key material")]
	InvalidKey,
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
mod tests {
	use super::*;
	use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

	#[test]
	fn generate_and_restore_roundtrip() {
		let (key, pkcs8) = AccountKey::generate().expect("generate");
		let restored = AccountKey::from_pkcs8(&pkcs8).expect("restore");
		// Same key → same public JWK.
		assert_eq!(key.jwk(), restored.jwk());
	}

	#[test]
	fn jwk_is_p256_ec() {
		let (key, _) = AccountKey::generate().expect("generate");
		let jwk = key.jwk();
		assert_eq!(jwk["kty"], "EC");
		assert_eq!(jwk["crv"], "P-256");
		assert!(jwk["x"].as_str().is_some_and(|x| !x.is_empty()));
		assert!(jwk["y"].as_str().is_some_and(|y| !y.is_empty()));
	}

	#[test]
	fn sign_produces_verifiable_flattened_jws() {
		let (key, _) = AccountKey::generate().expect("generate");
		let jws_str = key
			.sign(
				"https://acme.example/order",
				"nonce123",
				br#"{"x":1}"#,
				None,
			)
			.expect("sign");
		let jws: Value = serde_json::from_str(&jws_str).expect("json");

		let protected = jws["protected"].as_str().expect("protected");
		let payload = jws["payload"].as_str().expect("payload");
		let signature = B64
			.decode(jws["signature"].as_str().expect("sig"))
			.expect("b64 sig");

		// The signature verifies over `protected.payload`.
		let signing_input = format!("{protected}.{payload}");
		let public = key.key_pair.public_key().as_ref().to_vec();
		UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
			.verify(signing_input.as_bytes(), &signature)
			.expect("signature verifies");

		// newAccount form embeds the jwk, not a kid.
		let header: Value =
			serde_json::from_slice(&B64.decode(protected).expect("b64 header")).expect("header");
		assert_eq!(header["alg"], "ES256");
		assert_eq!(header["url"], "https://acme.example/order");
		assert!(header["jwk"].is_object());
		assert!(header["kid"].is_null());
	}

	#[test]
	fn thumbprint_is_stable_and_key_authorization_formats() {
		let (key, pkcs8) = AccountKey::generate().expect("generate");
		let restored = AccountKey::from_pkcs8(&pkcs8).expect("restore");
		// Deterministic for the same key.
		assert_eq!(key.thumbprint(), restored.thumbprint());
		// base64url has no padding.
		assert!(!key.thumbprint().contains('='));
		// Key authorization is token "." thumbprint.
		let auth = key.key_authorization("tok123");
		assert_eq!(auth, format!("tok123.{}", key.thumbprint()));

		// DNS-01 value is base64url(sha256(key authorization)): 43 chars, no pad.
		let dns = key.dns01_value("tok123");
		assert_eq!(dns.len(), 43, "{dns}");
		assert!(!dns.contains('='), "{dns}");
		assert_eq!(dns, restored.dns01_value("tok123"));
	}

	#[test]
	fn kid_form_omits_jwk() {
		let (key, _) = AccountKey::generate().expect("generate");
		let jws_str = key
			.sign(
				"https://acme.example/order",
				"n",
				b"{}",
				Some("https://acme.example/acct/1"),
			)
			.expect("sign");
		let jws: Value = serde_json::from_str(&jws_str).expect("json");
		let header: Value =
			serde_json::from_slice(&B64.decode(jws["protected"].as_str().unwrap()).unwrap())
				.unwrap();
		assert_eq!(header["kid"], "https://acme.example/acct/1");
		assert!(header["jwk"].is_null());
	}
}
