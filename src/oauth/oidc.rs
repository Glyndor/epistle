//! OpenID Connect discovery and JWKS handling for [`super::OauthVerifier`].
//!
//! When an operator configures a `discovery_url` instead of a static key, the
//! signing keys are fetched at startup from the IdP's published JWKS and cached.
//! Token verification then runs synchronously against the cache (no network in
//! the SASL auth path); a background task refreshes the cache so rotated keys
//! are picked up. JWK parameters are converted to the byte form `crate::jwt`
//! consumes: PKCS#1 DER for RSA, the raw uncompressed point for EC.

use serde::Deserialize;

use crate::jwt::Algorithm;

/// A single signing key parsed from a JWKS, ready for `crate::jwt::validate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
	/// Key id (`kid`), used to select the key matching a token header. Empty
	/// when the JWKS entry omits it.
	pub kid: String,
	/// The algorithm this key signs with.
	pub algorithm: Algorithm,
	/// The decoded key bytes: PKCS#1 DER for RSA, the `0x04‖x‖y` point for EC.
	pub key: Vec<u8>,
}

/// Why discovery, a JWKS fetch, or a JWKS parse failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcError {
	/// A discovery or JWKS URL was not `https://`.
	InsecureUrl,
	/// A network request failed.
	Network(String),
	/// A response body was not the expected JSON.
	BadJson(String),
	/// The discovery document had no `jwks_uri`.
	NoJwksUri,
	/// The JWKS contained no usable signing key.
	NoKeys,
}

impl std::fmt::Display for OidcError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			OidcError::InsecureUrl => f.write_str("OIDC endpoint must be https://"),
			OidcError::Network(e) => write!(f, "OIDC network error: {e}"),
			OidcError::BadJson(e) => write!(f, "OIDC malformed JSON: {e}"),
			OidcError::NoJwksUri => f.write_str("discovery document has no jwks_uri"),
			OidcError::NoKeys => f.write_str("JWKS contained no usable signing key"),
		}
	}
}

impl std::error::Error for OidcError {}

#[derive(Deserialize)]
struct Discovery {
	jwks_uri: String,
}

#[derive(Deserialize)]
struct JwkSet {
	keys: Vec<RawJwk>,
}

/// A raw JWK as published; only the fields we use are read.
#[derive(Deserialize)]
struct RawJwk {
	kty: String,
	#[serde(default)]
	kid: Option<String>,
	#[serde(default)]
	alg: Option<String>,
	#[serde(rename = "use", default)]
	use_: Option<String>,
	// RSA
	#[serde(default)]
	n: Option<String>,
	#[serde(default)]
	e: Option<String>,
	// EC
	#[serde(default)]
	crv: Option<String>,
	#[serde(default)]
	x: Option<String>,
	#[serde(default)]
	y: Option<String>,
}

/// Fetch the discovery document and then its JWKS over HTTPS, returning the
/// parsed signing keys. `default_alg` is applied to keys that omit their `alg`.
///
/// reqwest is built without the `json` feature here, so bodies are read with
/// `.text()` and parsed with `serde_json`, matching the other callers.
pub async fn fetch_keys(
	client: &reqwest::Client,
	discovery_url: &str,
	default_alg: Algorithm,
) -> Result<Vec<Jwk>, OidcError> {
	require_https(discovery_url)?;
	let body = get_text(client, discovery_url).await?;
	let discovery: Discovery =
		serde_json::from_str(&body).map_err(|e| OidcError::BadJson(e.to_string()))?;
	require_https(&discovery.jwks_uri)?;
	let jwks_body = get_text(client, &discovery.jwks_uri).await?;
	parse_jwks(&jwks_body, default_alg)
}

/// Reject any endpoint that is not HTTPS (fail closed: keys must arrive over a
/// confidential, authenticated channel).
fn require_https(url: &str) -> Result<(), OidcError> {
	if url.starts_with("https://") {
		Ok(())
	} else {
		Err(OidcError::InsecureUrl)
	}
}

async fn get_text(client: &reqwest::Client, url: &str) -> Result<String, OidcError> {
	client
		.get(url)
		.send()
		.await
		.map_err(|e| OidcError::Network(e.to_string()))?
		.text()
		.await
		.map_err(|e| OidcError::Network(e.to_string()))
}

/// Parse a JWKS JSON document into the supported signing keys. RSA (`kty:RSA`,
/// `n`/`e`) and EC P-256 (`kty:EC`, `crv:P-256`, `x`/`y`) keys are converted to
/// the bytes `crate::jwt` expects; unusable or unsupported entries are skipped.
/// Keys marked `use:enc` are skipped (signature verification only).
pub fn parse_jwks(body: &str, default_alg: Algorithm) -> Result<Vec<Jwk>, OidcError> {
	let set: JwkSet = serde_json::from_str(body).map_err(|e| OidcError::BadJson(e.to_string()))?;
	let mut keys = Vec::new();
	for raw in set.keys {
		if raw.use_.as_deref() == Some("enc") {
			continue;
		}
		if let Some(jwk) = convert_jwk(&raw, default_alg) {
			keys.push(jwk);
		}
	}
	if keys.is_empty() {
		return Err(OidcError::NoKeys);
	}
	Ok(keys)
}

/// Convert one raw JWK to a [`Jwk`], or `None` if it is malformed or of an
/// unsupported kind.
fn convert_jwk(raw: &RawJwk, default_alg: Algorithm) -> Option<Jwk> {
	let kid = raw.kid.clone().unwrap_or_default();
	match raw.kty.as_str() {
		"RSA" => {
			let n = b64url(raw.n.as_deref()?)?;
			let e = b64url(raw.e.as_deref()?)?;
			let algorithm = match raw.alg.as_deref() {
				Some(a) => parse_alg(a)?,
				None => Algorithm::Rs256,
			};
			if algorithm != Algorithm::Rs256 {
				return None;
			}
			Some(Jwk {
				kid,
				algorithm,
				key: rsa_pkcs1_der(&n, &e),
			})
		}
		"EC" => {
			// Only P-256 (ES256) is supported by crate::jwt.
			if raw.crv.as_deref() != Some("P-256") {
				return None;
			}
			let x = b64url(raw.x.as_deref()?)?;
			let y = b64url(raw.y.as_deref()?)?;
			if x.len() != 32 || y.len() != 32 {
				return None;
			}
			let algorithm = match raw.alg.as_deref() {
				Some(a) => parse_alg(a)?,
				None => default_alg,
			};
			if algorithm != Algorithm::Es256 {
				return None;
			}
			let mut point = Vec::with_capacity(65);
			point.push(0x04); // uncompressed point
			point.extend_from_slice(&x);
			point.extend_from_slice(&y);
			Some(Jwk {
				kid,
				algorithm,
				key: point,
			})
		}
		_ => None,
	}
}

fn parse_alg(alg: &str) -> Option<Algorithm> {
	match alg {
		"RS256" => Some(Algorithm::Rs256),
		"ES256" => Some(Algorithm::Es256),
		_ => None,
	}
}

fn b64url(value: &str) -> Option<Vec<u8>> {
	use base64::Engine;
	base64::engine::general_purpose::URL_SAFE_NO_PAD
		.decode(value)
		.ok()
}

/// Encode an RSA public key as DER `RSAPublicKey ::= SEQUENCE { modulus
/// INTEGER, publicExponent INTEGER }` (PKCS#1), the form ring's
/// `RSA_PKCS1_*` verifier consumes via `UnparsedPublicKey`.
fn rsa_pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
	let mut body = Vec::new();
	body.extend_from_slice(&der_integer(modulus));
	body.extend_from_slice(&der_integer(exponent));
	der_sequence(&body)
}

/// DER-encode an unsigned big-endian integer as an ASN.1 INTEGER. Leading zero
/// bytes are dropped, and a single `0x00` is prepended when the high bit is set
/// so the value stays positive.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
	let mut value: &[u8] = bytes;
	while value.len() > 1 && value[0] == 0x00 {
		value = &value[1..];
	}
	let mut content = Vec::new();
	if value.first().is_some_and(|b| b & 0x80 != 0) {
		content.push(0x00);
	}
	content.extend_from_slice(value);
	let mut out = vec![0x02]; // INTEGER tag
	out.extend_from_slice(&der_length(content.len()));
	out.extend_from_slice(&content);
	out
}

/// Wrap DER content in an ASN.1 SEQUENCE.
fn der_sequence(content: &[u8]) -> Vec<u8> {
	let mut out = vec![0x30]; // SEQUENCE tag
	out.extend_from_slice(&der_length(content.len()));
	out.extend_from_slice(content);
	out
}

/// Encode a DER length: short form below 128, else long form.
fn der_length(len: usize) -> Vec<u8> {
	if len < 0x80 {
		return vec![len as u8];
	}
	let mut bytes = Vec::new();
	let mut value = len;
	while value > 0 {
		bytes.insert(0, (value & 0xff) as u8);
		value >>= 8;
	}
	let mut out = vec![0x80 | bytes.len() as u8];
	out.extend_from_slice(&bytes);
	out
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;
