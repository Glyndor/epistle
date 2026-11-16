//! Answering a redeemed grant: the access token, and with refresh tokens
//! enabled the refresh token that goes with it, plus the
//! `grant_type=refresh_token` exchange itself.

use std::collections::HashMap;

use axum::Json;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use super::refresh::{self, FirstToken, MAX_REFRESH_TOKEN_CHARS, Outcome};
use super::scopes::Scopes;
use super::{AuthzServer, oauth_error};
use crate::api::ApiState;

/// The success body of a token response (RFC 6749 section 5.1).
fn token_response(
	authz: &AuthzServer,
	access_token: &str,
	scopes: &Scopes,
	refresh_token: Option<&str>,
) -> Response {
	let mut body = serde_json::json!({
		"access_token": access_token,
		"token_type": "Bearer",
		"expires_in": authz.access_ttl,
		"scope": scopes.as_string(),
	});
	if let Some(refresh_token) = refresh_token {
		body["refresh_token"] = serde_json::Value::String(refresh_token.to_string());
	}
	let mut response = Json(body).into_response();
	response
		.headers_mut()
		.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
	response
		.headers_mut()
		.insert(header::PRAGMA, "no-cache".parse().unwrap());
	response
}

/// Answer a redeemed device or authorization-code grant for `account`: sign the
/// access token and, when refresh tokens are enabled, start a family for it.
/// Fails closed: a store that cannot be written means no token at all.
pub(super) fn grant_tokens(
	state: &ApiState,
	authz: &AuthzServer,
	account: &str,
	scopes: &Scopes,
	now: u64,
) -> Response {
	let Some(access) = authz.issue_token(account, scopes, now) else {
		return oauth_error("server_error");
	};
	let Some(ttl) = authz.refresh_ttl else {
		return token_response(authz, &access, scopes, None);
	};
	// An account that gives no credential marker (the LDAP directory, a
	// receive-only account) could change its password without the refresh
	// token noticing, so it gets the short-lived access token alone.
	let Some(credential) = state.store().credential_fingerprint(account) else {
		return token_response(authz, &access, scopes, None);
	};
	let (Some(token), Some(family)) = (authz.random_code(), authz.random_code()) else {
		return oauth_error("server_error");
	};
	let scope = scopes.as_string();
	let first = FirstToken {
		token: &token,
		family: &family,
		account,
		scope: &scope,
		credential: &credential,
	};
	if refresh::start_family(state.data_dir(), &first, now.saturating_add(ttl), now).is_err() {
		return super::oauth_temporarily_unavailable(5);
	}
	token_response(authz, &access, scopes, Some(&token))
}

/// `grant_type=refresh_token` (RFC 6749 section 6): exchange a refresh token for
/// a new access token and a new refresh token. The scope may be narrowed, never
/// widened. Every refusal is `invalid_grant`, whatever its cause.
pub(super) fn redeem_refresh_token(
	state: &ApiState,
	authz: &AuthzServer,
	fields: &HashMap<String, String>,
	now: u64,
) -> Response {
	let Some(ttl) = authz.refresh_ttl else {
		return oauth_error("unsupported_grant_type");
	};
	let presented = fields
		.get("refresh_token")
		.map(String::as_str)
		.unwrap_or("");
	if presented.is_empty() || presented.len() > MAX_REFRESH_TOKEN_CHARS {
		return oauth_error("invalid_request");
	}
	let requested = match fields.get("scope") {
		Some(value) => match Scopes::parse(value) {
			Some(scopes) => Some(scopes),
			None => return oauth_error("invalid_scope"),
		},
		None => None,
	};
	let Some(next) = authz.random_code() else {
		return oauth_error("server_error");
	};
	let outcome = refresh::rotate(
		state.data_dir(),
		presented,
		&next,
		ttl,
		now,
		|account, credential| refresh::account_unchanged(state, account, credential),
		|granted| {
			requested.as_ref().is_none_or(|wanted| {
				Scopes::parse(granted).is_some_and(|granted| wanted.is_subset_of(&granted))
			})
		},
	);
	let (account, scope) = match outcome {
		Ok(Outcome::Rotated { account, scope }) => (account, scope),
		Ok(Outcome::ScopeTooWide) => return oauth_error("invalid_scope"),
		Ok(Outcome::Refused | Outcome::Reuse | Outcome::AccountChanged) => {
			return oauth_error("invalid_grant");
		}
		Err(_) => return super::oauth_temporarily_unavailable(5),
	};
	let scopes = match requested {
		Some(requested) => requested,
		None => match Scopes::parse(&scope) {
			Some(granted) => granted,
			None => return oauth_error("invalid_grant"),
		},
	};
	match authz.issue_token(&account, &scopes, now) {
		Some(access) => token_response(authz, &access, &scopes, Some(&next)),
		None => oauth_error("server_error"),
	}
}
