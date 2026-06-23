//! JSON Web Token validation (RFC 7519) for OAuth2/OIDC bearer authentication.
//!
//! The caller fixes the expected algorithm and supplies the public key, so the
//! token's own `alg` header can never downgrade verification (algorithm
//! confusion). Signature, expiry/not-before, and issuer/audience are all
//! checked; the validated claims are returned.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::Value;

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
	/// RSASSA-PKCS1-v1_5 with SHA-256.
	Rs256,
	/// ECDSA P-256 with SHA-256.
	Es256,
}

impl Algorithm {
	fn header_name(self) -> &'static str {
		match self {
			Algorithm::Rs256 => "RS256",
			Algorithm::Es256 => "ES256",
		}
	}

	fn verification(self) -> &'static dyn signature::VerificationAlgorithm {
		match self {
			Algorithm::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
			Algorithm::Es256 => &signature::ECDSA_P256_SHA256_FIXED,
		}
	}
}

/// Why a token failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
	/// Not three base64url parts, or a part is not valid base64url/JSON.
	Malformed,
	/// The `alg` header does not match the expected algorithm.
	AlgorithmMismatch,
	/// The signature did not verify against the key.
	BadSignature,
	/// `exp` is missing or not a number: a bearer token must have a bounded
	/// lifetime, so one without a usable `exp` is rejected (never accepted as
	/// non-expiring).
	MissingExpiry,
	/// `exp` is in the past.
	Expired,
	/// `nbf` is in the future.
	NotYetValid,
	/// `iss` does not match the expected issuer.
	WrongIssuer,
	/// `aud` does not contain the expected audience.
	WrongAudience,
}

/// The validated claims of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
	/// The full claims object, for application-specific fields.
	pub raw: Value,
}

impl Claims {
	/// A string claim, if present.
	pub fn string(&self, name: &str) -> Option<&str> {
		self.raw.get(name)?.as_str()
	}
}

/// What to require of a token's registered claims.
pub struct Validation<'a> {
	pub now: u64,
	pub issuer: Option<&'a str>,
	pub audience: Option<&'a str>,
}

/// Validate `token` with `algorithm` against `public_key` (DER SPKI for RSA, the
/// raw uncompressed point for EC), enforcing the registered claims.
pub fn validate(
	token: &str,
	algorithm: Algorithm,
	public_key: &[u8],
	validation: &Validation,
) -> Result<Claims, JwtError> {
	let mut parts = token.split('.');
	let (header_b64, payload_b64, signature_b64) =
		match (parts.next(), parts.next(), parts.next(), parts.next()) {
			(Some(h), Some(p), Some(s), None) => (h, p, s),
			_ => return Err(JwtError::Malformed),
		};

	let header: Value = decode_json(header_b64)?;
	if header.get("alg").and_then(Value::as_str) != Some(algorithm.header_name()) {
		return Err(JwtError::AlgorithmMismatch);
	}

	let signature = B64URL
		.decode(signature_b64)
		.map_err(|_| JwtError::Malformed)?;
	let signing_input = format!("{header_b64}.{payload_b64}");
	signature::UnparsedPublicKey::new(algorithm.verification(), public_key)
		.verify(signing_input.as_bytes(), &signature)
		.map_err(|_| JwtError::BadSignature)?;

	let claims: Value = decode_json(payload_b64)?;
	check_claims(&claims, validation)?;
	Ok(Claims { raw: claims })
}

fn check_claims(claims: &Value, validation: &Validation) -> Result<(), JwtError> {
	// A bearer token MUST carry a bounded lifetime: a missing or non-numeric
	// `exp` is rejected outright rather than treated as "never expires".
	let exp = claims
		.get("exp")
		.and_then(Value::as_u64)
		.ok_or(JwtError::MissingExpiry)?;
	if validation.now >= exp {
		return Err(JwtError::Expired);
	}
	if let Some(nbf) = claims.get("nbf").and_then(Value::as_u64)
		&& validation.now < nbf
	{
		return Err(JwtError::NotYetValid);
	}
	if let Some(expected) = validation.issuer
		&& claims.get("iss").and_then(Value::as_str) != Some(expected)
	{
		return Err(JwtError::WrongIssuer);
	}
	if let Some(expected) = validation.audience
		&& !audience_matches(claims.get("aud"), expected)
	{
		return Err(JwtError::WrongAudience);
	}
	Ok(())
}

/// `aud` may be a string or an array of strings (RFC 7519 §4.1.3).
fn audience_matches(aud: Option<&Value>, expected: &str) -> bool {
	match aud {
		Some(Value::String(value)) => value == expected,
		Some(Value::Array(values)) => values.iter().any(|v| v.as_str() == Some(expected)),
		_ => false,
	}
}

/// Why signing a token failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
	/// The algorithm is not supported for signing (only ES256 is).
	UnsupportedAlgorithm,
	/// The PKCS#8 private key could not be parsed.
	BadKey,
	/// The claims could not be serialized to JSON.
	BadClaims,
	/// The CSPRNG failed or the signature operation failed.
	SigningFailed,
}

/// Sign `claims` into a compact JWS (`base64url(header).base64url(payload).
/// base64url(signature)`) using `algorithm` and `private_key_pkcs8` (a PKCS#8
/// DER ES256 private key).
///
/// Only ES256 is supported (the authorization server's own tokens are ES256);
/// any other algorithm fails closed with [`SignError::UnsupportedAlgorithm`].
/// The header is `{"alg":"ES256","typ":"JWT"}`. The resulting token verifies
/// with [`validate`] against the matching public point.
pub fn sign(
	claims: &Value,
	algorithm: Algorithm,
	private_key_pkcs8: &[u8],
) -> Result<String, SignError> {
	if algorithm != Algorithm::Es256 {
		return Err(SignError::UnsupportedAlgorithm);
	}
	let rng = SystemRandom::new();
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, private_key_pkcs8, &rng)
		.map_err(|_| SignError::BadKey)?;
	let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
	let header_b64 = B64URL.encode(serde_json::to_vec(&header).map_err(|_| SignError::BadClaims)?);
	let payload_b64 = B64URL.encode(serde_json::to_vec(claims).map_err(|_| SignError::BadClaims)?);
	let signing_input = format!("{header_b64}.{payload_b64}");
	let signature = pair
		.sign(&rng, signing_input.as_bytes())
		.map_err(|_| SignError::SigningFailed)?;
	Ok(format!(
		"{signing_input}.{}",
		B64URL.encode(signature.as_ref())
	))
}

fn decode_json(part: &str) -> Result<Value, JwtError> {
	let bytes = B64URL.decode(part).map_err(|_| JwtError::Malformed)?;
	serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)
}

#[cfg(test)]
mod tests;
