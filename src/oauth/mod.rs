//! OAuth2/OIDC bearer-token verification for SASL (OAUTHBEARER/XOAUTH2).
//!
//! Validates a bearer JWT against a configured issuer, audience and signing
//! key, returning the authenticated identity (the email/sub claim). The SASL
//! mechanism wiring consumes this.

use crate::jwt::{self, Algorithm, Validation};

/// A configured token verifier.
pub struct OauthVerifier {
	issuer: String,
	audience: String,
	algorithm: Algorithm,
	public_key: Vec<u8>,
}

/// Why a verifier could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
	/// The `algorithm` was not RS256 or ES256.
	UnsupportedAlgorithm,
	/// The base64 public key was malformed.
	BadKey,
}

impl OauthVerifier {
	/// Build from configuration: the algorithm name (`ES256`/`RS256`) and the
	/// base64-encoded public key (SPKI DER for RSA, raw point for EC).
	pub fn new(
		issuer: impl Into<String>,
		audience: impl Into<String>,
		algorithm: &str,
		public_key_b64: &str,
	) -> Result<Self, BuildError> {
		use base64::Engine;
		let algorithm = match algorithm.to_ascii_uppercase().as_str() {
			"RS256" => Algorithm::Rs256,
			"ES256" => Algorithm::Es256,
			_ => return Err(BuildError::UnsupportedAlgorithm),
		};
		let public_key = base64::engine::general_purpose::STANDARD
			.decode(public_key_b64.trim())
			.map_err(|_| BuildError::BadKey)?;
		Ok(OauthVerifier {
			issuer: issuer.into(),
			audience: audience.into(),
			algorithm,
			public_key,
		})
	}

	/// Verify a bearer token at `now_secs`, returning the authenticated email
	/// (the `email` claim, falling back to `sub`) when it is valid.
	pub fn verify(&self, token: &str, now_secs: u64) -> Option<String> {
		let validation = Validation {
			now: now_secs,
			issuer: Some(&self.issuer),
			audience: Some(&self.audience),
		};
		let claims = jwt::validate(token, self.algorithm, &self.public_key, &validation).ok()?;
		claims
			.string("email")
			.or_else(|| claims.string("sub"))
			.map(str::to_string)
	}
}

impl std::fmt::Debug for OauthVerifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("OauthVerifier")
			.field("issuer", &self.issuer)
			.field("audience", &self.audience)
			.field("algorithm", &self.algorithm)
			.finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
	use ring::rand::SystemRandom;
	use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

	fn signed_token(pair: &EcdsaKeyPair, rng: &SystemRandom, claims: &serde_json::Value) -> String {
		let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
		let payload = B64URL.encode(serde_json::to_vec(claims).unwrap());
		let input = format!("{header}.{payload}");
		let sig = pair.sign(rng, input.as_bytes()).unwrap();
		format!("{input}.{}", B64URL.encode(sig.as_ref()))
	}

	#[test]
	fn verifies_token_and_returns_email() {
		let rng = SystemRandom::new();
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
			.unwrap();
		let public_b64 = B64.encode(pair.public_key().as_ref());

		let verifier =
			OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64).expect("build");
		let token = signed_token(
			&pair,
			&rng,
			&serde_json::json!({
				"iss": "https://idp.example",
				"aud": "mail",
				"email": "alice@example.org",
				"exp": 2000,
			}),
		);
		assert_eq!(
			verifier.verify(&token, 1000).as_deref(),
			Some("alice@example.org")
		);
		// Expired or wrong-issuer tokens do not verify.
		assert_eq!(verifier.verify(&token, 3000), None);
	}

	#[test]
	fn rejects_bad_configuration() {
		assert!(matches!(
			OauthVerifier::new("i", "a", "HS256", "AAAA"),
			Err(BuildError::UnsupportedAlgorithm)
		));
		assert!(matches!(
			OauthVerifier::new("i", "a", "ES256", "not base64!!!"),
			Err(BuildError::BadKey)
		));
	}

	#[test]
	fn builds_rs256_verifier() {
		// The RS256 algorithm arm is accepted; the key bytes are decoded lazily.
		let verifier = OauthVerifier::new("i", "a", "rs256", "AAAA").expect("build");
		assert!(format!("{verifier:?}").contains("OauthVerifier"));
	}

	#[test]
	fn falls_back_to_sub_when_email_absent() {
		let rng = SystemRandom::new();
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
			.unwrap();
		let public_b64 = B64.encode(pair.public_key().as_ref());
		let verifier =
			OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64).expect("build");
		let token = signed_token(
			&pair,
			&rng,
			&serde_json::json!({
				"iss": "https://idp.example",
				"aud": "mail",
				"sub": "user-123",
				"exp": 2000,
			}),
		);
		assert_eq!(verifier.verify(&token, 1000).as_deref(), Some("user-123"));
	}
}
