//! The Authorization Code grant with PKCE (RFC 7636, S256 only) and the shared
//! `POST /oauth/token` endpoint.
//!
//! - `POST /oauth/authorize` (authenticated by account credentials, since epistle
//!   is headless): issue a one-time `authorization_code` bound to the account and
//!   the supplied S256 `code_challenge`.
//! - `POST /oauth/token` dispatches on `grant_type` to either the device-code
//!   redemption ([`super::device::redeem_device_code`]) or the authorization-code
//!   redemption here, verifying the PKCE `code_verifier`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

use super::{
	ACCESS_TOKEN_TTL_SECS, AuthCode, CODE_TTL_SECS, constant_time_eq, oauth_error, parse_fields,
};
use crate::api::ApiState;

/// The grant-type identifier for the device-code flow (RFC 8628 §3.4).
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Current Unix time in seconds (0 on the impossible pre-epoch clock).
fn now_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// The success body of a token response (RFC 6749 §5.1).
pub(crate) fn token_response(access_token: &str) -> Json<serde_json::Value> {
	Json(serde_json::json!({
		"access_token": access_token,
		"token_type": "Bearer",
		"expires_in": ACCESS_TOKEN_TTL_SECS,
	}))
}

/// `POST /oauth/authorize` (authenticated): issue an authorization code bound to
/// the authenticated account and the S256 `code_challenge`. The caller proves an
/// account identity with `login`+`password` (form/JSON) or HTTP Basic.
///
/// Fail-closed: only `code_challenge_method=S256` is accepted (plain is
/// rejected); bad credentials and a missing/empty challenge are rejected; the
/// issued code is single-use and short-lived.
pub async fn authorize(
	State(state): State<ApiState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Response {
	let Some(authz) = state.authz() else {
		return oauth_error("invalid_request");
	};
	let fields = parse_fields(&headers, &body);

	// S256 only: a missing or `plain` method is rejected (RFC 7636 §4.3 downgrade
	// protection — we never accept the weaker transformation).
	if fields.get("code_challenge_method").map(String::as_str) != Some("S256") {
		return oauth_error("invalid_request");
	}
	let code_challenge = fields.get("code_challenge").cloned().unwrap_or_default();
	if code_challenge.is_empty()
		|| fields
			.get("client_id")
			.map(String::is_empty)
			.unwrap_or(true)
	{
		return oauth_error("invalid_request");
	}

	let Some((login, password)) = super::device::account_credentials_pub(&headers, &fields) else {
		return oauth_error("invalid_grant");
	};
	let Some(account) = state.authenticate(&login, &password) else {
		return oauth_error("invalid_grant");
	};

	let Some(code) = authz.random_code() else {
		return oauth_error("server_error");
	};
	let now = now_secs();
	authz
		.codes
		.lock()
		.unwrap_or_else(|p| p.into_inner())
		.insert(
			code.clone(),
			AuthCode {
				account,
				code_challenge,
				expires_at: now + CODE_TTL_SECS,
			},
		);
	let mut response = serde_json::json!({ "code": code });
	if let Some(state_param) = fields.get("state") {
		response["state"] = serde_json::Value::String(state_param.clone());
	}
	Json(response).into_response()
}

/// `POST /oauth/token` (public): dispatch on `grant_type` and return a signed
/// JWT access token on success, or an RFC 6749/8628 error JSON otherwise.
pub async fn token(
	State(state): State<ApiState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Response {
	let Some(authz) = state.authz() else {
		return oauth_error("invalid_request");
	};
	let fields = parse_fields(&headers, &body);
	match fields.get("grant_type").map(String::as_str) {
		Some(DEVICE_CODE_GRANT) => {
			let device_code = fields.get("device_code").map(String::as_str).unwrap_or("");
			if device_code.is_empty() {
				return oauth_error("invalid_request");
			}
			super::device::redeem_device_code(authz, device_code)
		}
		Some("authorization_code") => redeem_authorization_code(authz, &fields),
		_ => oauth_error("unsupported_grant_type"),
	}
}

/// Verify a PKCE `code_verifier` against the stored S256 `code_challenge`, one-
/// time-use the code, and issue the token. Fail-closed: a mismatched verifier,
/// an expired or already-redeemed code, or signing failure all deny.
fn redeem_authorization_code(
	authz: &super::AuthzServer,
	fields: &std::collections::HashMap<String, String>,
) -> Response {
	let code = fields.get("code").map(String::as_str).unwrap_or("");
	let verifier = fields
		.get("code_verifier")
		.map(String::as_str)
		.unwrap_or("");
	if code.is_empty() || verifier.is_empty() {
		return oauth_error("invalid_request");
	}
	let now = now_secs();
	// Remove the code up front: even on a verifier mismatch it is consumed, so a
	// stolen code cannot be brute-forced across requests (one-time, always).
	let stored = authz
		.codes
		.lock()
		.unwrap_or_else(|p| p.into_inner())
		.remove(code);
	let Some(stored) = stored else {
		return oauth_error("invalid_grant");
	};
	if stored.expires_at <= now {
		return oauth_error("invalid_grant");
	}
	// BASE64URL(SHA256(code_verifier)) == code_challenge (RFC 7636 §4.6).
	let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
	let computed = B64URL.encode(digest.as_ref());
	if !constant_time_eq(computed.as_bytes(), stored.code_challenge.as_bytes()) {
		return oauth_error("invalid_grant");
	}
	match authz.issue_token(&stored.account, now) {
		Some(token) => token_response(&token).into_response(),
		None => oauth_error("server_error"),
	}
}
