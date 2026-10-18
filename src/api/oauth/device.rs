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
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::{
	AuthzServer, CODE_TTL_SECS, DeviceGrant, POLL_INTERVAL_SECS, oauth_error, parse_fields,
};
use crate::api::ApiState;
use crate::util::constant_time;

/// Grants alive at once, over all clients. A pending grant is a few hundred
/// bytes, so this bounds the memory an unauthenticated caller can pin, and the
/// linear scan `device_approve` does under the same lock.
pub(super) const MAX_DEVICE_GRANTS: usize = 10_000;
/// Grants alive at once for one client (an IPv4 address or an IPv6 /64).
pub(super) const MAX_GRANTS_PER_CLIENT: usize = 10;
/// Grants alive at once for one IPv6 /48.
pub(super) const MAX_GRANTS_PER_NET: usize = 100;

/// What a client is for the per-client cap: the address for IPv4, the /64 for
/// IPv6 (one host there owns the whole /64).
pub(super) fn client_bucket(ip: std::net::IpAddr) -> (bool, u64) {
	match ip {
		std::net::IpAddr::V4(v4) => (false, u64::from(u32::from(v4))),
		std::net::IpAddr::V6(v6) => (true, (u128::from(v6) >> 64) as u64),
	}
}

/// The /48 of an IPv6 client (the cap on one allocation); an IPv4 address is
/// its own.
fn net48_of(client: Option<(bool, u64)>) -> Option<(bool, u64)> {
	client.map(|(v6, bits)| {
		if v6 {
			(true, bits >> 16)
		} else {
			(false, bits)
		}
	})
}

/// The group a client is counted in when the pool is full: an IPv6 /32 (an
/// attacker spreading grants over many /48s of one allocation stays one
/// group), or the address for IPv4.
fn group_of(client: Option<(bool, u64)>) -> Option<(bool, u64)> {
	client.map(|(v6, bits)| {
		if v6 {
			(true, bits >> 32)
		} else {
			(false, bits)
		}
	})
}

/// Store `grant` under `device_code` if the policy allows it, `false` if not.
///
/// The policy, whole:
/// 1. A client, and an IPv6 /48, may hold only so many grants, and the pool
///    only [`MAX_DEVICE_GRANTS`]. Expired grants are dropped first.
/// 2. A client or /48 over its cap is refused.
/// 3. With the pool full, the oldest pending grant of the group (an IPv6 /32,
///    or an IPv4 address) holding the most pending grants is evicted, provided
///    that group holds strictly more than the requester's own. If the
///    requester's group is itself the heaviest, or nothing is pending, it is
///    refused.
/// 4. An approved grant is never evicted and is not counted in 3.
///
/// So a newcomer always gets in while anyone is above it, a heavy group can
/// only ever displace itself, and the endpoint's request rate stays limited
/// per origin. Residual risk: an attacker with many distinct /32s (or IPv4
/// addresses) each holding a little can fill the pool with groups no heavier
/// than a legitimate newcomer; the grants expire after ten minutes.
fn admit(
	devices: &std::sync::Mutex<std::collections::HashMap<String, DeviceGrant>>,
	device_code: String,
	grant: DeviceGrant,
	now: u64,
) -> bool {
	let mut devices = devices.lock().unwrap_or_else(|p| p.into_inner());
	let client = grant.client;
	let net = net48_of(client);
	let over_cap = |devices: &std::collections::HashMap<String, DeviceGrant>| {
		devices.values().filter(|g| g.client == client).count() >= MAX_GRANTS_PER_CLIENT
			|| (net.is_some_and(|n| n.0)
				&& devices
					.values()
					.filter(|g| net48_of(g.client) == net)
					.count() >= MAX_GRANTS_PER_NET)
	};
	if devices.len() >= MAX_DEVICE_GRANTS || over_cap(&devices) {
		// Expired grants nobody polled for would otherwise count forever.
		devices.retain(|_, g| g.expires_at > now);
	}
	if over_cap(&devices) {
		return false;
	}
	if devices.len() >= MAX_DEVICE_GRANTS {
		let mut pending: std::collections::HashMap<Option<(bool, u64)>, usize> =
			std::collections::HashMap::new();
		for g in devices.values().filter(|g| g.approved_account.is_none()) {
			*pending.entry(group_of(g.client)).or_default() += 1;
		}
		let mine = pending.get(&group_of(client)).copied().unwrap_or(0);
		let Some((heaviest, count)) = pending.into_iter().max_by_key(|(_, n)| *n) else {
			return false;
		};
		if count <= mine {
			return false;
		}
		let oldest = devices
			.iter()
			.filter(|(_, g)| g.approved_account.is_none() && group_of(g.client) == heaviest)
			.min_by_key(|(_, g)| g.expires_at)
			.map(|(code, _)| code.clone());
		if let Some(code) = oldest {
			devices.remove(&code);
		}
	}
	devices.insert(device_code, grant);
	true
}

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
	peer: Option<axum::Extension<ConnectInfo<std::net::SocketAddr>>>,
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
	let client = peer.map(|axum::Extension(ConnectInfo(addr))| {
		client_bucket(crate::net::canonical_peer(addr).ip())
	});
	let grant = DeviceGrant {
		user_code: user_code.clone(),
		approved_account: None,
		expires_at: now + CODE_TTL_SECS,
		next_poll_at: now,
		client,
	};
	if !admit(&authz.devices, device_code.clone(), grant, now) {
		return (
			StatusCode::TOO_MANY_REQUESTS,
			Json(serde_json::json!({ "error": "slow_down" })),
		)
			.into_response();
	}
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
	ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
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
	// not the user_code exists (no timing oracle on code existence). The OAuth
	// grant endpoints sit outside `require_bearer_token`, so the peer IP is
	// sourced from `ConnectInfo` here; wired in by the listener's
	// `into_make_service_with_connect_info`; and forwarded to the ban-aware
	// authentication path. A dual-stack `::` listener reports an IPv4 peer as
	// `::ffff:a.b.c.d`; canonicalize so the ban / audit pipeline sees a plain
	// `IpAddr::V4`.
	let peer = crate::net::canonical_peer(peer);
	let account = credentials.and_then(|(login, password)| {
		// The OAuth approval flow is a user-facing API authentication: the
		// account must opt into `api` in its `allowed_protocols` to bind a
		// grant, matching how `/api/v1/auth/verify` tags its callers.
		state.authenticate_with_ip(
			&login,
			&password,
			Some(peer.ip()),
			crate::config::Protocol::Api,
		)
	});

	let now = now_secs();
	let mut devices = authz.devices.lock().unwrap_or_else(|p| p.into_inner());
	let grant = devices.values_mut().find(|g| {
		constant_time::eq(g.user_code.as_bytes(), user_code.as_bytes()) && g.expires_at > now
	});
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
