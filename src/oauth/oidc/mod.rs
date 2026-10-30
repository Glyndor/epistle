//! OpenID Connect discovery and JWKS handling for [`super::OauthVerifier`].
//!
//! When an operator configures a `discovery_url` instead of a static key, the
//! signing keys are fetched at startup from the IdP's published JWKS and cached.
//! Token verification then runs synchronously against the cache (no network in
//! the SASL auth path); a background task refreshes the cache so rotated keys
//! are picked up. JWK parameters are converted to the byte form `crate::jwt`
//! consumes: PKCS#1 DER for RSA, the raw uncompressed point for EC.
//!
//! The `jwks_uri` named by the discovery document is fetched as a second
//! request. That URL is chosen by the IdP, not the operator, so a hostile or
//! compromised IdP could point it at an internal address (cloud metadata at
//! `169.254.169.254`, a service on the LAN, ...). The off-scope screen
//! refuses to fetch such a `jwks_uri` by default; the operator must opt
//! in with `[oauth] allow_private_jwks = true` (documented, off by
//! default). The opt-in is the single gate because every other rationale
//! a legitimate internal IdP can offer ("the same address is also
//! reachable from the discovery host", "the JWKS points at the IdP
//! itself") also describes a successful SSRF pivot on top of an honest
//! IdP, and trusting the network after the fact gives the pivot back to
//! the attacker.

use std::net::{IpAddr, ToSocketAddrs};

use crate::net::{HttpsUrl, HttpsUrlError};
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
	/// The `jwks_uri` named by the discovery document resolves to a private,
	/// loopback, link-local or unspecified address that does not coincide with
	/// any address the discovery URL itself resolves to. The string is the
	/// resolved internal address (or addresses) that triggered the rejection,
	/// so an operator can see exactly what the IdP tried to pivot to.
	JwksUriOffScope(String),
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
			OidcError::JwksUriOffScope(address) => write!(
				f,
				"OIDC jwks_uri resolves to {address}, which is not the discovery host"
			),
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

/// DNS resolution as a dependency so the off-scope screen can be tested with a
/// stub that returns canned addresses for a given host name. The default
/// [`SystemResolver`] is what production uses; tests pass their own.
pub trait NameResolver: Send + Sync {
	/// Every IPv4 / IPv6 address `name` currently points at. An empty result
	/// (host did not resolve) is reported as a network error so a typo in the
	/// discovery doc does not silently fall through.
	fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, OidcError>;
}

/// The production resolver: `getaddrinfo` over stdlib, one address family at a
/// time. Tests use this when they want the real network, or substitute their
/// own to pin the addresses the screen sees.
pub struct SystemResolver;

impl NameResolver for SystemResolver {
	fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, OidcError> {
		let addrs = (name, 443u16)
			.to_socket_addrs()
			.map_err(|e| OidcError::Network(format!("DNS resolution for {name}: {e}")))?;
		Ok(addrs.map(|a| a.ip()).collect())
	}
}

/// Fetch the discovery document and then its JWKS over HTTPS, returning the
/// parsed signing keys. `default_alg` is applied to keys that omit their `alg`.
///
/// `resolver` is the DNS dependency used by the off-scope screen (production
/// passes [`SystemResolver`], tests pass a stub). `allow_private_jwks`
/// controls whether a `jwks_uri` that resolves to an internal address is
/// allowed to fetch.
///
/// reqwest is built without the `json` feature here, so bodies are read with
/// `.text()` and parsed with `serde_json`, matching the other callers.
pub async fn fetch_keys(
	client: &reqwest::Client,
	discovery_url: &HttpsUrl,
	default_alg: Algorithm,
	allow_private_jwks: bool,
	resolver: &dyn NameResolver,
) -> Result<Vec<Jwk>, OidcError> {
	let body = get_text(client, discovery_url).await?;
	let discovery: Discovery =
		serde_json::from_str(&body).map_err(|e| OidcError::BadJson(e.to_string()))?;
	let jwks_uri = parse_endpoint(&discovery.jwks_uri)?;
	ensure_jwks_uri_in_scope(discovery_url, &jwks_uri, allow_private_jwks, resolver).await?;
	let jwks_body = get_text(client, &jwks_uri).await?;
	parse_jwks(&jwks_body, default_alg)
}

/// Confirm the `jwks_uri` published by the IdP does not pivot to a host the
/// operator did not choose. Returns `Ok(())` when every resolved address is
/// public, or when `allow_private_jwks` is true (explicit opt-in by the
/// operator; documented in `docs/configuration.md`).
///
/// Resolving the host goes through `resolver` so tests can pin the addresses
/// the screen sees instead of standing up a real DNS server.
///
/// This is a screen, not a guarantee: between the resolve here and the actual
/// connect in `get_text`, DNS may rotate and a second query can return a
/// different address (TOCTOU). Closing that window means binding the socket to
/// the already-resolved IP before connecting, which is a separate piece of work
/// not done here.
pub(crate) async fn ensure_jwks_uri_in_scope(
	discovery_url: &HttpsUrl,
	jwks_uri: &HttpsUrl,
	allow_private_jwks: bool,
	resolver: &dyn NameResolver,
) -> Result<(), OidcError> {
	let jwks_ips = collect_ips(jwks_uri, resolver).await?;
	if jwks_uri_allowed(&jwks_ips, &[], allow_private_jwks) {
		return Ok(());
	}
	let discovery_ips = collect_ips(discovery_url, resolver).await?;
	if jwks_uri_allowed(&jwks_ips, &discovery_ips, allow_private_jwks) {
		Ok(())
	} else {
		let offending = jwks_ips
			.iter()
			.copied()
			.filter(|ip| is_internal(*ip))
			.map(|ip| ip.to_string())
			.collect::<Vec<_>>()
			.join(", ");
		Err(OidcError::JwksUriOffScope(offending))
	}
}

/// Test-only entry point. Same as [`ensure_jwks_uri_in_scope`] but reachable
/// from the test module so the screen can be exercised against a stub
/// resolver without round-tripping the HTTPS client.
#[cfg(test)]
pub(crate) async fn ensure_jwks_uri_in_scope_for_test(
	discovery_url: &HttpsUrl,
	jwks_uri: &HttpsUrl,
	allow_private_jwks: bool,
	resolver: &dyn NameResolver,
) -> Result<(), OidcError> {
	ensure_jwks_uri_in_scope(discovery_url, jwks_uri, allow_private_jwks, resolver).await
}

/// Every address `url` currently points at: the literal IPv4 / IPv6 in the
/// host, or every address a DNS lookup of the host name returns. An empty
/// result (host did not resolve) is reported as a network error so a typo in
/// the discovery doc does not silently fall through.
async fn collect_ips(
	url: &HttpsUrl,
	resolver: &dyn NameResolver,
) -> Result<Vec<IpAddr>, OidcError> {
	match url.as_url().host() {
		Some(url::Host::Ipv4(ip)) => Ok(vec![IpAddr::V4(ip)]),
		Some(url::Host::Ipv6(ip)) => Ok(vec![IpAddr::V6(ip)]),
		Some(url::Host::Domain(name)) => resolver.lookup(name),
		None => Err(OidcError::Network(format!("OIDC URL {url} has no host"))),
	}
}

/// True when `ip` is private (RFC 1918 / RFC 4193), loopback, link-local or
/// unspecified — i.e. an address an attacker could use to pivot to a service
/// the operator did not choose to expose. IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
/// is unwrapped to its IPv4 payload so a v6 URL cannot hide a v4 internal
/// address from the check.
fn is_internal(ip: IpAddr) -> bool {
	match ip {
		IpAddr::V4(v4) => {
			v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
		}
		IpAddr::V6(v6) => {
			if let Some(v4) = v6.to_ipv4_mapped() {
				return v4.is_private()
					|| v4.is_loopback()
					|| v4.is_link_local()
					|| v4.is_unspecified();
			}
			v6.is_loopback()
				|| v6.is_unspecified()
				|| v6.is_unique_local()
				|| v6.is_unicast_link_local()
		}
	}
}

/// Pure decision extracted from [`ensure_jwks_uri_in_scope`] so the policy can
/// be tested without DNS. Returns true when the jwks set is allowed: every
/// address in it is public, or the operator opted in to private jwks URIs
/// with `[oauth] allow_private_jwks = true`.
///
/// Self-pivot (a jwks set whose every internal address is also reachable from
/// the discovery URL) is intentionally not allowed by the default policy.
/// A "Keycloak on the LAN whose own JWKS points at itself" deployment has a
/// clean fix at the operator level: set `allow_private_jwks = true` and
/// accept the documented risk. Letting self-pivot act as an implicit opt-in
/// would also describe a successful SSRF pivot on top of an honest IdP, and
/// after the fact the network cannot tell those two situations apart.
pub(crate) fn jwks_uri_allowed(
	jwks_ips: &[IpAddr],
	discovery_ips: &[IpAddr],
	allow_private_jwks: bool,
) -> bool {
	let internal: Vec<IpAddr> = jwks_ips
		.iter()
		.copied()
		.filter(|ip| is_internal(*ip))
		.collect();
	if internal.is_empty() {
		return true;
	}
	if allow_private_jwks {
		return true;
	}
	// `all`, not `any`. A jwks set that resolves to the discovery host and one
	// other internal address would, with `any`, pass on the self-pivot and
	// leave the other address unsupervised.
	internal.iter().all(|ip| discovery_ips.contains(ip))
}

/// Parse a discovery or JWKS endpoint, refusing anything that is not HTTPS
/// (fail closed: keys must arrive over a confidential, authenticated channel).
/// The returned [`HttpsUrl`] is the only form [`fetch_keys`] accepts, so the
/// scheme cannot be skipped by a caller.
pub fn parse_endpoint(text: &str) -> Result<HttpsUrl, OidcError> {
	HttpsUrl::parse(text).map_err(|e| match e {
		HttpsUrlError::NotHttps => OidcError::InsecureUrl,
		other => OidcError::Network(format!("invalid OIDC URL: {other}")),
	})
}

async fn get_text(client: &reqwest::Client, url: &HttpsUrl) -> Result<String, OidcError> {
	// Discovery and JWKS documents are small; read the body in chunks with a
	// hard cap so a hostile or compromised IdP cannot exhaust memory with a
	// huge (or endless) response. Paired with the client's no-redirect policy,
	// this closes the discovery-fetch SSRF/DoS surface.
	const MAX_BODY: usize = 256 * 1024;
	let mut response = client
		.get(url.as_url().clone())
		.send()
		.await
		.map_err(|e| OidcError::Network(e.to_string()))?;
	let mut body = Vec::new();
	while let Some(chunk) = response
		.chunk()
		.await
		.map_err(|e| OidcError::Network(e.to_string()))?
	{
		if body.len() + chunk.len() > MAX_BODY {
			return Err(OidcError::Network("discovery response too large".into()));
		}
		body.extend_from_slice(&chunk);
	}
	String::from_utf8(body).map_err(|e| OidcError::Network(e.to_string()))
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
mod tests;
