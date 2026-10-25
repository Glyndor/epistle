//! OAuth2/OIDC bearer-token verification for SASL (OAUTHBEARER/XOAUTH2).
//!
//! Validates a bearer JWT against a configured issuer, audience and signing
//! key, returning the authenticated identity (the verified `email` claim). The
//! SASL mechanism wiring consumes this.

use std::sync::{Arc, RwLock};

use crate::jwt::{self, Algorithm, Validation};

mod identity;
pub use identity::Verified;
pub mod oidc;

pub use oidc::{Jwk, OidcError};

/// The signing-key source backing a verifier.
enum KeySource {
	/// A single statically configured key.
	Static {
		algorithm: Algorithm,
		public_key: Vec<u8>,
	},
	/// Keys fetched from an OIDC JWKS, refreshed in the background. Selected per
	/// token by `kid`. Shared so the refresh task can swap the contents while
	/// `verify` reads them, with no network in the (sync) verify path.
	Jwks(Arc<RwLock<Vec<Jwk>>>),
}

/// A configured token verifier.
pub struct OauthVerifier {
	issuer: String,
	audience: String,
	source: KeySource,
	policy: identity::IdentityPolicy,
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
			source: KeySource::Static {
				algorithm,
				public_key,
			},
			policy: identity::IdentityPolicy::default(),
		})
	}

	/// Build a verifier backed by keys fetched from an OIDC JWKS. The returned
	/// handle holds the shared cache the background refresh task swaps into; the
	/// initial `keys` are populated at startup (see [`Self::jwks_cache`]).
	pub fn from_jwks(
		issuer: impl Into<String>,
		audience: impl Into<String>,
		keys: Vec<Jwk>,
	) -> Self {
		OauthVerifier {
			issuer: issuer.into(),
			audience: audience.into(),
			source: KeySource::Jwks(Arc::new(RwLock::new(keys))),
			policy: identity::IdentityPolicy::default(),
		}
	}

	/// Set what the operator declares about the identity provider: whether it
	/// may vouch for an `email` claim without `email_verified`, and whether it
	/// enforces its own second factor on the sign-in that issues a token.
	pub fn with_identity_policy(
		mut self,
		allow_unverified_email: bool,
		second_factor_attested: bool,
	) -> Self {
		self.policy = identity::IdentityPolicy {
			allow_unverified_email,
			second_factor_attested,
			..self.policy
		};
		self
	}

	/// [`Self::with_identity_policy`] with what the `[oauth]` section declares.
	/// Tokens signed with the key of epistle's own authorization server
	/// (`signing_key` or `signing_key_file`) name an account in `sub` and
	/// come after the second factor was asked for.
	pub fn declared_by(mut self, config: &crate::config::Oauth) -> Self {
		self.policy.own_tokens = config.signing_key.is_some() || config.signing_key_file.is_some();
		self.with_identity_policy(
			config.allow_unverified_email,
			config.idp_enforces_second_factor,
		)
	}

	/// Treat every token as one of epistle's own authorization server.
	#[cfg(test)]
	pub(crate) fn with_own_tokens(mut self) -> Self {
		self.policy.own_tokens = true;
		self
	}

	/// Whether a token of this verifier stands for the second factor: the
	/// operator declared that the identity provider enforces one, or the
	/// tokens come from epistle's own authorization server, which asks for
	/// it before issuing. When it does not, an account with a TOTP secret
	/// cannot sign in with a bearer token.
	pub fn second_factor_attested(&self) -> bool {
		self.policy.second_factor_met()
	}

	/// The shared JWKS cache, when this verifier is OIDC-backed. The background
	/// refresh task replaces its contents with freshly fetched keys.
	pub fn jwks_cache(&self) -> Option<Arc<RwLock<Vec<Jwk>>>> {
		match &self.source {
			KeySource::Jwks(cache) => Some(Arc::clone(cache)),
			KeySource::Static { .. } => None,
		}
	}

	/// Verify a bearer token at `now_secs`, returning the authenticated email
	/// (the `email` claim, which must carry `email_verified` unless the
	/// operator declared otherwise) when it is valid. Synchronous and
	/// network-free: OIDC keys are read from the in-memory cache.
	pub fn verify(&self, token: &str, now_secs: u64) -> Option<String> {
		self.verify_identity(token, now_secs)
			.map(|verified| verified.as_str().to_string())
	}

	/// Verify a bearer token and say who it names. A refusal is logged with
	/// its reason and nothing taken from the token.
	pub fn verify_identity(&self, token: &str, now_secs: u64) -> Option<Verified> {
		let claims = match self.validate(token, now_secs) {
			Ok(claims) => claims,
			// A client that keeps its old token is routine, not a fault.
			Err(jwt::JwtError::Expired) => {
				tracing::info!("bearer token refused: it has expired");
				return None;
			}
			Err(error) => {
				tracing::warn!("bearer token refused: {}", invalid_reason(&error));
				return None;
			}
		};
		match self.policy.identity(&claims) {
			Ok(verified) => Some(verified),
			Err(refusal) => {
				tracing::warn!("bearer token refused: {}", refusal.reason());
				None
			}
		}
	}

	fn validate(&self, token: &str, now_secs: u64) -> Result<crate::jwt::Claims, jwt::JwtError> {
		let validation = Validation {
			now: now_secs,
			issuer: Some(&self.issuer),
			audience: Some(&self.audience),
		};
		match &self.source {
			KeySource::Static {
				algorithm,
				public_key,
			} => jwt::validate(token, *algorithm, public_key, &validation),
			KeySource::Jwks(cache) => {
				let kid = token_kid(token);
				let keys = cache.read().map_err(|_| jwt::JwtError::BadSignature)?;
				let key = select_key(&keys, kid.as_deref()).ok_or(jwt::JwtError::BadSignature)?;
				jwt::validate(token, key.algorithm, &key.key, &validation)
			}
		}
	}
}

/// Why a token does not validate, as the log states it.
fn invalid_reason(error: &jwt::JwtError) -> &'static str {
	use jwt::JwtError::*;
	match error {
		Malformed | AlgorithmMismatch => "it is not a token this verifier can read",
		BadSignature => "its signature does not verify against a known key",
		MissingExpiry => "it has no usable exp claim",
		Expired => "it has expired",
		NotYetValid => "it is not valid yet (nbf)",
		WrongIssuer => "its issuer is not the configured one",
		WrongAudience => "its audience is not the configured one",
	}
}

/// Parse the `kid` from a JWT header without verifying anything (the header is
/// only used to select which cached key to verify against).
fn token_kid(token: &str) -> Option<String> {
	use base64::Engine;
	let header_b64 = token.split('.').next()?;
	let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.decode(header_b64)
		.ok()?;
	let header: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
	header.get("kid")?.as_str().map(str::to_string)
}

/// Select the cached key matching a token's `kid`. When the token has no `kid`
/// and exactly one key is cached, fall back to it; otherwise an unknown `kid`
/// is rejected (fail closed — the next refresh will pick up a new key).
fn select_key<'a>(keys: &'a [Jwk], kid: Option<&str>) -> Option<&'a Jwk> {
	match kid {
		Some(kid) => keys.iter().find(|k| k.kid == kid),
		None => {
			if keys.len() == 1 {
				keys.first()
			} else {
				None
			}
		}
	}
}

impl std::fmt::Debug for OauthVerifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let source = match &self.source {
			KeySource::Static { algorithm, .. } => format!("static {algorithm:?}"),
			KeySource::Jwks(_) => "jwks".to_string(),
		};
		f.debug_struct("OauthVerifier")
			.field("issuer", &self.issuer)
			.field("audience", &self.audience)
			.field("source", &source)
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
				"email_verified": true,
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
	fn a_token_with_only_a_subject_names_no_identity() {
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
		assert_eq!(verifier.verify(&token, 1000), None);
	}

	/// Sign an ES256 token whose header carries `kid`, like an IdP-issued token.
	fn signed_token_kid(
		pair: &EcdsaKeyPair,
		rng: &SystemRandom,
		kid: &str,
		claims: &serde_json::Value,
	) -> String {
		let header = B64URL.encode(format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#));
		let payload = B64URL.encode(serde_json::to_vec(claims).unwrap());
		let input = format!("{header}.{payload}");
		let sig = pair.sign(rng, input.as_bytes()).unwrap();
		format!("{input}.{}", B64URL.encode(sig.as_ref()))
	}

	fn ec_keypair() -> (EcdsaKeyPair, SystemRandom, Vec<u8>) {
		let rng = SystemRandom::new();
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
			.unwrap();
		let point = pair.public_key().as_ref().to_vec();
		(pair, rng, point)
	}

	#[test]
	fn jwks_verifier_selects_key_by_kid_and_verifies() {
		let (pair, rng, point) = ec_keypair();
		// Two cached keys; the token's kid selects the right one.
		let keys = vec![
			Jwk {
				kid: "other".to_string(),
				algorithm: Algorithm::Es256,
				key: vec![0x04; 65],
			},
			Jwk {
				kid: "live".to_string(),
				algorithm: Algorithm::Es256,
				key: point,
			},
		];
		let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
		let token = signed_token_kid(
			&pair,
			&rng,
			"live",
			&serde_json::json!({
				"iss": "https://idp.example",
				"aud": "mail",
				"email": "bob@example.org",
				"email_verified": true,
				"exp": 2000,
			}),
		);
		assert_eq!(
			verifier.verify(&token, 1000).as_deref(),
			Some("bob@example.org")
		);
	}

	#[test]
	fn jwks_verifier_rejects_unknown_kid() {
		let (pair, rng, point) = ec_keypair();
		let keys = vec![Jwk {
			kid: "known".to_string(),
			algorithm: Algorithm::Es256,
			key: point,
		}];
		let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
		let token = signed_token_kid(
			&pair,
			&rng,
			"unknown",
			&serde_json::json!({"iss": "https://idp.example", "aud": "mail", "exp": 2000}),
		);
		assert_eq!(verifier.verify(&token, 1000), None);
	}

	#[test]
	fn jwks_verifier_rejects_wrong_issuer_and_audience() {
		let (pair, rng, point) = ec_keypair();
		let keys = vec![Jwk {
			kid: "k".to_string(),
			algorithm: Algorithm::Es256,
			key: point,
		}];
		let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
		let bad_issuer = signed_token_kid(
			&pair,
			&rng,
			"k",
			&serde_json::json!({"iss": "https://evil.example", "aud": "mail", "exp": 2000}),
		);
		assert_eq!(verifier.verify(&bad_issuer, 1000), None);
		let bad_audience = signed_token_kid(
			&pair,
			&rng,
			"k",
			&serde_json::json!({"iss": "https://idp.example", "aud": "other", "exp": 2000}),
		);
		assert_eq!(verifier.verify(&bad_audience, 1000), None);
	}

	#[test]
	fn jwks_verifier_uses_the_single_key_without_kid() {
		let (pair, rng, point) = ec_keypair();
		let keys = vec![Jwk {
			kid: String::new(),
			algorithm: Algorithm::Es256,
			key: point,
		}];
		let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
		// No-kid header: the single cached key is used.
		let token = signed_token(
			&pair,
			&rng,
			&serde_json::json!({
				"iss": "https://idp.example",
				"aud": "mail",
				"email": "carol@example.org",
				"email_verified": true,
				"exp": 2000,
			}),
		);
		assert_eq!(
			verifier.verify(&token, 1000).as_deref(),
			Some("carol@example.org")
		);
	}

	#[test]
	fn jwks_cache_is_exposed_for_static_and_oidc() {
		let oidc = OauthVerifier::from_jwks("i", "a", vec![]);
		assert!(oidc.jwks_cache().is_some());
		let static_v = OauthVerifier::new("i", "a", "ES256", "AAAA").expect("build");
		assert!(static_v.jwks_cache().is_none());
	}
}
