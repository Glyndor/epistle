//! Durable revocations, shared by processes through the existing locked store.
//! Only hashes of signed token IDs and expiry times reach disk.

use std::collections::HashMap;
use std::path::Path;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::api::ApiState;

const FILE: &str = "oauth_revocations.json";

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocations {
	revoked: HashMap<String, u64>,
}

fn id_hash(id: &str) -> String {
	crate::api::api_keys::sha256_hash(id)
}

pub(super) fn is_live(dir: &Path, id: &str, now: u64) -> bool {
	match std::fs::read(dir.join(FILE)) {
		Ok(bytes) => match serde_json::from_slice::<Revocations>(&bytes) {
			Ok(store) => store
				.revoked
				.get(&id_hash(id))
				.is_none_or(|expiry| *expiry <= now),
			Err(_) => false,
		},
		Err(error) => error.kind() == std::io::ErrorKind::NotFound,
	}
}

/// RFC 7009: possession of a valid token permits revoking only that token.
/// Invalid/expired/already revoked tokens receive the same empty success body.
pub(super) async fn revoke(
	State(state): State<ApiState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Response {
	let fields = super::parse_fields(&headers, &body);
	let Some(token) = fields.get("token") else {
		return super::oauth_error("invalid_request");
	};
	let Some(now) = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.ok()
		.map(|d| d.as_secs())
	else {
		return super::oauth_error("server_error");
	};
	let Some(claims) = state.authz().and_then(|a| a.access_claims(token, now)) else {
		// Not an access token of this server: it may be a refresh token, whose
		// whole family ends with it (RFC 7009 section 2.1).
		if state.authz().is_some_and(|a| a.refresh_ttl.is_some())
			&& super::refresh::revoke(state.data_dir(), token, now).is_err()
		{
			return (
				StatusCode::SERVICE_UNAVAILABLE,
				axum::Json(serde_json::json!({"error": "temporarily_unavailable"})),
			)
				.into_response();
		}
		return StatusCode::OK.into_response();
	};
	let (Some(id), Some(expiry)) = (
		claims.string("jti"),
		claims.raw.get("exp").and_then(serde_json::Value::as_u64),
	) else {
		return StatusCode::OK.into_response();
	};
	let result = crate::storage::locked::edit(
		&state.data_dir().join(FILE),
		|text| serde_json::from_str::<Revocations>(text).map_err(std::io::Error::other),
		|store| serde_json::to_string(store).map_err(std::io::Error::other),
		Revocations::default,
		|store| -> std::io::Result<()> {
			store.revoked.retain(|_, expiry| *expiry > now);
			store.revoked.insert(id_hash(id), expiry);
			Ok(())
		},
	);
	if result.is_err() {
		return (
			StatusCode::SERVICE_UNAVAILABLE,
			axum::Json(serde_json::json!({"error": "temporarily_unavailable"})),
		)
			.into_response();
	}
	StatusCode::OK.into_response()
}
