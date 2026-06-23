//! Built-in OAuth 2.0 authorization server for epistle's own access tokens.
//!
//! epistle is headless (no browser UI), so it issues its own bearer tokens
//! through two grants a CLI / mail client can drive:
//!
//! - the Device Authorization Grant (RFC 8628), with user approval over an
//!   authenticated API endpoint rather than an HTML page, and
//! - the Authorization Code grant with PKCE (RFC 7636, S256 only).
//!
//! Issued tokens are ES256 JWTs signed with the configured `[oauth] signing_key`
//! and carrying the configured `iss`/`aud`; they verify with the very same
//! [`crate::oauth::OauthVerifier`] that accepts OAUTHBEARER tokens, because the
//! signing key's public point is the configured `[oauth] public_key`.
//!
//! Everything fails closed: high-entropy codes from the system CSPRNG, one-time
//! use, bounded expiry, S256-only PKCE, and — when no signing key is configured
//! — the routes are not mounted at all (no unsigned tokens are ever issued).

use std::collections::HashMap;
use std::sync::Mutex;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;

use crate::jwt::{self, Algorithm};

mod device;
mod pkce;

pub use device::{device_approve, device_authorization};
pub use pkce::{authorize, token};

/// How long a pending device authorization or authorization code stays valid.
const CODE_TTL_SECS: u64 = 600;
/// Minimum seconds a device-flow client must wait between token polls.
const POLL_INTERVAL_SECS: u64 = 5;
/// Lifetime of an issued access token.
const ACCESS_TOKEN_TTL_SECS: u64 = 3600;
/// Unambiguous alphabet for the human `user_code` (no 0/O/1/I/L).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";

/// The authorization-server runtime: the ES256 signing key, the token claims to
/// stamp, and the in-memory grant stores. Present on [`super::ApiState`] only
/// when `[oauth] signing_key` is configured.
pub struct AuthzServer {
	/// Base64-decoded PKCS#8 DER ES256 private key used to sign access tokens.
	signing_key: Vec<u8>,
	/// `iss` claim stamped on issued tokens (the configured OAuth issuer).
	issuer: String,
	/// `aud` claim stamped on issued tokens (the configured OAuth audience).
	audience: String,
	/// Pending device authorizations, keyed by the opaque `device_code`.
	devices: Mutex<HashMap<String, DeviceGrant>>,
	/// Issued, not-yet-redeemed authorization codes, keyed by the `code`.
	codes: Mutex<HashMap<String, AuthCode>>,
	rng: SystemRandom,
}

/// A pending device authorization (RFC 8628 §3.2).
struct DeviceGrant {
	/// The human code the user types into the approval endpoint.
	user_code: String,
	/// Set to the approved account identity once approved; `None` while pending.
	approved_account: Option<String>,
	/// Unix seconds after which this grant is expired.
	expires_at: u64,
	/// Earliest Unix second the client may poll the token endpoint again.
	next_poll_at: u64,
}

/// An issued authorization code bound to an account and a PKCE challenge.
struct AuthCode {
	/// The authenticated account the code was issued for.
	account: String,
	/// The S256 `code_challenge` the redeeming `code_verifier` must match.
	code_challenge: String,
	/// Unix seconds after which this code is expired.
	expires_at: u64,
}

impl AuthzServer {
	/// Build the authorization server from the base64 PKCS#8 ES256 signing key and
	/// the issuer/audience to stamp on issued tokens. Returns `None` if the key is
	/// not valid base64 (fail closed: no server, no tokens).
	pub fn new(
		signing_key_b64: &str,
		issuer: impl Into<String>,
		audience: impl Into<String>,
	) -> Option<Self> {
		let signing_key = base64::engine::general_purpose::STANDARD
			.decode(signing_key_b64.trim())
			.ok()?;
		Some(AuthzServer {
			signing_key,
			issuer: issuer.into(),
			audience: audience.into(),
			devices: Mutex::new(HashMap::new()),
			codes: Mutex::new(HashMap::new()),
			rng: SystemRandom::new(),
		})
	}

	/// Sign an access-token JWT for `account`, valid for [`ACCESS_TOKEN_TTL_SECS`]
	/// from `now`. The `sub` is the account identity, matching what the verifier
	/// returns. `None` only if signing fails (fail closed).
	fn issue_token(&self, account: &str, now: u64) -> Option<String> {
		let claims = serde_json::json!({
			"sub": account,
			"iss": self.issuer,
			"aud": self.audience,
			"iat": now,
			"exp": now + ACCESS_TOKEN_TTL_SECS,
		});
		jwt::sign(&claims, Algorithm::Es256, &self.signing_key).ok()
	}

	/// A high-entropy URL-safe opaque code (32 bytes from the CSPRNG). `None` if
	/// the CSPRNG fails (fail closed — no low-entropy fallback).
	fn random_code(&self) -> Option<String> {
		let mut bytes = [0u8; 32];
		self.rng.fill(&mut bytes).ok()?;
		Some(B64URL.encode(bytes))
	}

	/// A short human `user_code` (`XXXX-XXXX`) from the unambiguous alphabet,
	/// using rejection-free CSPRNG bytes. `None` if the CSPRNG fails.
	fn random_user_code(&self) -> Option<String> {
		let mut bytes = [0u8; 8];
		self.rng.fill(&mut bytes).ok()?;
		let mut out = String::with_capacity(9);
		for (i, byte) in bytes.iter().enumerate() {
			if i == 4 {
				out.push('-');
			}
			let index = (*byte as usize) % USER_CODE_ALPHABET.len();
			out.push(USER_CODE_ALPHABET[index] as char);
		}
		Some(out)
	}
}

/// Constant-time-ish byte comparison: always scans both inputs fully, so a
/// mismatch leaks neither the position nor (beyond length) the expected value.
/// Used to compare PKCE challenges.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}
	diff == 0
}

/// Parse a request body that is either `application/x-www-form-urlencoded` or
/// `application/json` (an object of string values) into a field map. Anything
/// else, or a malformed body, yields an empty map — the handler then rejects on
/// the missing required field (fail closed, no panic on hostile input).
pub(crate) fn parse_fields(headers: &HeaderMap, body: &Bytes) -> HashMap<String, String> {
	let content_type = headers
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.unwrap_or("");
	if content_type.contains("application/json") {
		match serde_json::from_slice::<Value>(body) {
			Ok(Value::Object(map)) => map
				.into_iter()
				.filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
				.collect(),
			_ => HashMap::new(),
		}
	} else {
		// Treat everything else as form-encoded (the OAuth default media type).
		parse_form(body)
	}
}

/// Parse an `application/x-www-form-urlencoded` body into a field map, decoding
/// `+` to space and `%XX` escapes. Self-contained (no extra dependency); bad
/// escapes are passed through literally rather than panicking.
fn parse_form(body: &[u8]) -> HashMap<String, String> {
	let text = String::from_utf8_lossy(body);
	let mut fields = HashMap::new();
	for pair in text.split('&') {
		if pair.is_empty() {
			continue;
		}
		let (key, value) = match pair.split_once('=') {
			Some((k, v)) => (form_decode(k), form_decode(v)),
			None => (form_decode(pair), String::new()),
		};
		fields.entry(key).or_insert(value);
	}
	fields
}

/// Decode one `application/x-www-form-urlencoded` token.
fn form_decode(token: &str) -> String {
	let bytes = token.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		match bytes[i] {
			b'+' => out.push(b' '),
			b'%' if i + 2 < bytes.len() => {
				let hi = (bytes[i + 1] as char).to_digit(16);
				let lo = (bytes[i + 2] as char).to_digit(16);
				match (hi, lo) {
					(Some(hi), Some(lo)) => {
						out.push((hi * 16 + lo) as u8);
						i += 2;
					}
					_ => out.push(b'%'),
				}
			}
			other => out.push(other),
		}
		i += 1;
	}
	String::from_utf8_lossy(&out).into_owned()
}

/// An RFC 6749 / 8628 OAuth error response: `{"error": "..."}` with HTTP 400
/// (or 429 for `slow_down`). The body never reveals which of several inputs was
/// wrong beyond the registered error code.
pub(crate) fn oauth_error(code: &'static str) -> Response {
	let status = if code == "slow_down" {
		StatusCode::TOO_MANY_REQUESTS
	} else {
		StatusCode::BAD_REQUEST
	};
	(status, Json(serde_json::json!({ "error": code }))).into_response()
}

/// Build the public OAuth router (the `token` and `device_authorization`
/// endpoints; no auth — the codes are the credential). Mounted only when the
/// authorization server is configured.
pub fn public_router() -> Router<super::ApiState> {
	Router::new()
		.route("/oauth/token", post(token))
		.route("/oauth/device_authorization", post(device_authorization))
}

/// Build the authenticated OAuth router (device approval and the PKCE authorize
/// endpoint; the caller proves an account identity with its credentials).
pub fn authenticated_router() -> Router<super::ApiState> {
	Router::new()
		.route("/oauth/device/approve", post(device_approve))
		.route("/oauth/authorize", post(authorize))
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
