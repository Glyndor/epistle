//! The OAuth 2.0 Device Authorization Grant endpoints (RFC 8628).
//!
//! - `POST /oauth/device_authorization` (public): start a flow, returning the
//!   device and user codes.
//! - `POST /oauth/device/approve` (authenticated by account credentials): the
//!   headless equivalent of the user clicking "approve" on a verification page.
//! - the `device_code` arm of `POST /oauth/token` lives in [`super::pkce::token`],
//!   which calls [`redeem_device_code`].

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use super::{
	AuthzServer, CODE_TTL_SECS, DeviceGrant, POLL_INTERVAL_SECS, oauth_error, parse_fields,
};
use crate::api::ApiState;

/// Current Unix time in seconds (0 on the impossible pre-epoch clock).
fn now_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// `POST /oauth/device_authorization` (RFC 8628 §3.1–3.2): begin a device flow.
/// Accepts `client_id` (and an optional `scope`) as form or JSON, and returns
/// the device/user codes and polling parameters. Public: the codes themselves
/// are the only credential.
pub async fn device_authorization(
	State(state): State<ApiState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Response {
	let Some(authz) = state.authz() else {
		return oauth_error("invalid_request");
	};
	let fields = parse_fields(&headers, &body);
	// RFC 8628 requires client_id; reject its absence rather than mint a code.
	if fields
		.get("client_id")
		.map(String::as_str)
		.unwrap_or("")
		.is_empty()
	{
		return oauth_error("invalid_request");
	}
	let (Some(device_code), Some(user_code)) = (authz.random_code(), authz.random_user_code())
	else {
		// CSPRNG failure: never issue a low-entropy code.
		return oauth_error("server_error");
	};
	let now = now_secs();
	let grant = DeviceGrant {
		user_code: user_code.clone(),
		approved_account: None,
		expires_at: now + CODE_TTL_SECS,
		next_poll_at: now,
	};
	authz
		.devices
		.lock()
		.unwrap_or_else(|p| p.into_inner())
		.insert(device_code.clone(), grant);
	// epistle is headless: the verification URI is the approval endpoint a user
	// (or CLI) posts the user_code and credentials to.
	let verification_uri = "/oauth/device/approve";
	Json(serde_json::json!({
		"device_code": device_code,
		"user_code": user_code,
		"verification_uri": verification_uri,
		"verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
		"expires_in": CODE_TTL_SECS,
		"interval": POLL_INTERVAL_SECS,
	}))
	.into_response()
}

/// `POST /oauth/device/approve` (authenticated, headless approval): the user
/// presents `user_code` plus account credentials (`login`+`password` as form or
/// JSON, or HTTP Basic). On success the matching device grant is marked approved
/// for that account.
///
/// Fail-closed: a wrong user_code, an unknown account, or a bad password all
/// return the same `400 invalid_grant` — the response never reveals which input
/// was wrong (no user-enumeration / code-probing oracle).
pub async fn device_approve(
	State(state): State<ApiState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Response {
	let Some(authz) = state.authz() else {
		return oauth_error("invalid_request");
	};
	let fields = parse_fields(&headers, &body);
	let user_code = fields.get("user_code").cloned().unwrap_or_default();
	let credentials = account_credentials(&headers, &fields);

	// Authenticate first, unconditionally, so the work done is the same whether or
	// not the user_code exists (no timing oracle on code existence).
	let account = credentials.and_then(|(login, password)| state.authenticate(&login, &password));

	let now = now_secs();
	let mut devices = authz.devices.lock().unwrap_or_else(|p| p.into_inner());
	let grant = devices
		.values_mut()
		.find(|g| g.user_code == user_code && g.expires_at > now);
	match (grant, account) {
		(Some(grant), Some(account)) => {
			grant.approved_account = Some(account);
			Json(serde_json::json!({ "status": "approved" })).into_response()
		}
		// Either the code is wrong/expired or the credentials are wrong: one answer.
		_ => oauth_error("invalid_grant"),
	}
}

/// Crate-visible re-export of [`account_credentials`] for the PKCE authorize
/// endpoint, which authenticates the same way.
pub(crate) fn account_credentials_pub(
	headers: &HeaderMap,
	fields: &std::collections::HashMap<String, String>,
) -> Option<(String, String)> {
	account_credentials(headers, fields)
}

/// Extract `login`/`password` from form/JSON fields or an HTTP Basic header.
fn account_credentials(
	headers: &HeaderMap,
	fields: &std::collections::HashMap<String, String>,
) -> Option<(String, String)> {
	if let (Some(login), Some(password)) = (fields.get("login"), fields.get("password")) {
		return Some((login.clone(), password.clone()));
	}
	basic_auth(headers)
}

/// Decode an HTTP Basic `Authorization` header into `(login, password)`.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
	use base64::Engine;
	let value = headers
		.get(axum::http::header::AUTHORIZATION)?
		.to_str()
		.ok()?
		.strip_prefix("Basic ")?;
	let decoded = base64::engine::general_purpose::STANDARD
		.decode(value)
		.ok()?;
	let text = String::from_utf8(decoded).ok()?;
	let (login, password) = text.split_once(':')?;
	Some((login.to_string(), password.to_string()))
}

/// Redeem a `device_code` at the token endpoint (RFC 8628 §3.4–3.5). Returns the
/// signed access-token JSON once approved, or the appropriate pending/error
/// response. Enforces the minimum poll interval (`slow_down`), expiry
/// (`expired_token`), and one-time consumption of the code on success.
pub fn redeem_device_code(authz: &AuthzServer, device_code: &str) -> Response {
	let now = now_secs();
	let mut devices = authz.devices.lock().unwrap_or_else(|p| p.into_inner());
	let Some(grant) = devices.get_mut(device_code) else {
		// Unknown or already-consumed code.
		return oauth_error("invalid_grant");
	};
	if grant.expires_at <= now {
		devices.remove(device_code);
		return oauth_error("expired_token");
	}
	if now < grant.next_poll_at {
		// Polling too fast: tell the client to back off (RFC 8628 §3.5).
		grant.next_poll_at = now + POLL_INTERVAL_SECS;
		return oauth_error("slow_down");
	}
	grant.next_poll_at = now + POLL_INTERVAL_SECS;
	let Some(account) = grant.approved_account.clone() else {
		return oauth_error("authorization_pending");
	};
	// Approved: consume the code (one-time) and issue the token.
	devices.remove(device_code);
	drop(devices);
	match authz.issue_token(&account, now) {
		Some(token) => super::pkce::token_response(&token).into_response(),
		None => oauth_error("server_error"),
	}
}
