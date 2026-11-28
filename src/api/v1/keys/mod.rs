//! `/api/v1/keys`: list, make and revoke API keys, by the rules `epistle
//! api-key` follows ([`crate::api::api_keys::issue`]).
//!
//! The scope is `key`, and only `key`. A key that makes keys is the way to
//! every other, so what it makes reaches no further than it does: no scope it
//! does not hold, no domain outside its own, no wider network, no later
//! expiry, no account outside its domains. It lists and revokes only the keys
//! it could have made, and another key it cannot reach is the same `404` as
//! one that is not there. The secret of a new key is in the answer to the
//! request that made it, once, and the answer is marked `no-store`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;

use crate::api::api_keys::issue::{self, Ask, Issuer, Reach, Refusal, World};
use crate::api::api_keys::{
	ApiKey, ApiKeyStore, ApiKeySummary, display_names, sha256_hash, stored_form,
};
use crate::api::audit::{Carried, KeyEvent, log_key_change};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::api::{ApiKeySet, Principal};

/// Largest body a write takes.
pub(super) const MAX_BODY: usize = 4096;
/// Hard ceiling on page size.
const MAX_LIMIT: usize = 200;
/// The page size when the caller names none.
const DEFAULT_LIMIT: usize = 50;

/// The server as the rules see it.
struct Server<'a>(&'a ApiState);

impl World for Server<'_> {
	fn account_known(&self, name: &str) -> bool {
		self.0.store().account_known(name)
	}

	fn account_addresses(&self, name: &str) -> Vec<String> {
		self.0
			.accounts()
			.into_iter()
			.find(|account| account.name == name)
			.map(|account| account.addresses)
			.unwrap_or_default()
	}

	fn hosts(&self, domain: &str) -> bool {
		self.0
			.domains()
			.iter()
			.any(|hosted| hosted.eq_ignore_ascii_case(domain))
	}
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
}

/// The answer to a refused request.
fn refusal(refusal: Refusal) -> ApiError {
	match refusal {
		Refusal::Invalid(message) => ApiError::invalid_input(&message),
		Refusal::Policy(message) => ApiError::invalid_input(&message),
		Refusal::Escalation(message) => ApiError::forbidden(&format!(
			"a key cannot make a key that reaches further than itself: {message}"
		)),
	}
}

/// The key that asks, `None` for the configured token. Anything else is refused
/// before the keys are looked at.
fn asking(principal: &Principal) -> Result<Option<issue::Caller>, ApiError> {
	match principal.issuer() {
		Issuer::Operator => Ok(None),
		Issuer::Key(caller) => Ok(Some(caller)),
		Issuer::Nobody => Err(ApiError::forbidden("the key that asked is no longer valid")),
	}
}

fn not_found() -> ApiError {
	ApiError::not_found("no such API key")
}

/// Whether the caller reaches `key`: every key for the configured token, and
/// for a key the ones it could have made.
fn reaches(state: &ApiState, caller: Option<&Reach>, key: &ApiKey) -> bool {
	let Some(caller) = caller else {
		return true;
	};
	let addresses = key
		.account
		.as_deref()
		.map(|name| Server(state).account_addresses(name));
	caller.covers(&Reach::of_key(key, addresses)).is_ok()
}

/// The query of `GET /api/v1/keys`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
	limit: Option<usize>,
	/// The `next_cursor` of the page before.
	cursor: Option<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(query): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
	let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
	if limit == 0 {
		return Err(ApiError::field_out_of_range(
			"limit",
			"limit must be at least 1",
		));
	}
	let principal = Principal::for_token(&state, &auth);
	let caller = asking(&principal)?.map(|caller| caller.reach().clone());
	let mut rows: Vec<ApiKeySummary> = state
		.api_keys()
		.snapshot()
		.iter()
		.filter(|key| reaches(&state, caller.as_ref(), key))
		.map(ApiKeySummary::of)
		.collect();
	rows.sort_by(|a, b| a.label.cmp(&b.label));
	if let Some(cursor) = &query.cursor {
		rows.retain(|row| row.label.as_str() > cursor.as_str());
	}
	let more = rows.len() > limit;
	rows.truncate(limit);
	let next_cursor = more
		.then(|| rows.last().map(|row| row.label.clone()))
		.flatten();
	let mut body =
		serde_json::json!({ "keys": rows.iter().map(ApiKeySummary::json).collect::<Vec<_>>() });
	if let Some(cursor) = next_cursor {
		body["next_cursor"] = cursor.into();
	}
	Ok(Json(body))
}

/// The body of `POST /api/v1/keys`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
	label: String,
	scopes: Vec<String>,
	#[serde(default)]
	domains: Vec<String>,
	#[serde(default)]
	account: Option<String>,
	/// When the key stops working: epoch seconds, a date, an RFC 3339 instant
	/// or a duration from now, as `epistle api-key create --expires-at`.
	#[serde(default)]
	expires_at: Option<String>,
	/// A duration from now such as `90d`; not with `expires_at`.
	#[serde(default)]
	expires_in: Option<String>,
	#[serde(default)]
	ip_cidr: Option<String>,
	#[serde(default)]
	auto_submitted: bool,
}

pub async fn create(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Json(body): Json<Create>,
) -> Result<Response, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let expires_at = match (&body.expires_at, &body.expires_in) {
		(Some(_), Some(_)) => {
			return Err(ApiError::invalid_input(
				"name expires_at or expires_in, not both",
			));
		}
		(Some(when), None) => Some(
			crate::cli::api_keys::expiry::parse_expires_at(when)
				.map_err(|message| ApiError::value_not_allowed("expires_at", &message))?,
		),
		(None, Some(span)) => Some(
			crate::cli::api_keys::expiry::parse_expires_in(span)
				.map_err(|message| ApiError::value_not_allowed("expires_in", &message))?,
		),
		(None, None) => None,
	};
	if expires_at.is_some_and(|at| at <= now()) {
		return Err(ApiError::value_not_allowed(
			"expires_at",
			"the expiry is in the past",
		));
	}
	let request = issue::Request {
		label: body.label,
		expires_at,
		ip_cidr: body.ip_cidr,
		scopes: body.scopes,
		domains: body
			.domains
			.iter()
			.map(|d| d.to_ascii_lowercase())
			.collect(),
		account: body.account,
		max_domains: Some(issue::MAX_DOMAINS),
	};
	let caller = asking(&principal)?;
	// `api-key create` takes one or the other. The rule is not one of
	// `issue::check`: the hidden `api-key-create` alias runs it too and still
	// takes both, for the scripts that pass them.
	if request.account.is_some() && !request.domains.is_empty() {
		return Err(ApiError::invalid_input(
			"a key bound to an account cannot also be confined to domains: name account or domains",
		));
	}
	let wanted = issue::check(&request, caller.as_ref(), &Server(&state)).map_err(refusal)?;
	let secret = crate::util::secret::generate_secret().ok_or_else(|| {
		tracing::error!("no randomness for an API key");
		ApiError::internal()
	})?;
	// Both spellings of the scopes, as the store writes them, so the answer is
	// the key as it is kept.
	let (scopes, grants) = stored_form(&request.scopes, request.account.is_some())
		.map_err(|error| ApiError::invalid_input(&error.to_string()))?;
	let key = ApiKey {
		label: request.label.clone(),
		hash: sha256_hash(&secret),
		expires_at: request.expires_at,
		ip_cidr: request.ip_cidr.clone(),
		scopes,
		grants,
		domains: request.domains.clone(),
		account: request.account.clone(),
		auto_submitted: body.auto_submitted,
	};
	let gate = match (&key.account, state.live_domains()) {
		(Some(name), Some(live)) => Some(
			crate::directory_store::AccountStore::gate_from_config(&live.current(), name).map_err(
				|error| {
					tracing::error!(%error, "the limits of the account cannot be read");
					ApiError::internal()
				},
			)?,
		),
		_ => None,
	};
	let by = principal.key_label().map(str::to_owned);
	let carried = Carried::capture();
	let (data_dir, set) = (state.data_dir().to_path_buf(), Arc::clone(state.api_keys()));
	let (label, scopes) = (
		key.label.clone(),
		display_names(&key.scopes, &key.grants).to_vec(),
	);
	// The write and its line are made together on a thread a client that goes
	// away does not stop.
	let world = state;
	let written = tokio::task::spawn_blocking(move || {
		let mut store = ApiKeyStore::open(&data_dir)?;
		// The world the file is asked about under its own lock: the facts
		// of the server are read there, not from the request. The account of
		// a bound key stays held until the file is written.
		let server = Server(&world);
		let ask = caller.as_ref().map(|caller| Ask {
			caller,
			wanted: &wanted,
			max_keys: issue::MAX_KEYS_BY_KEY,
			world: &server,
		});
		store.add_bound(key.clone(), gate.as_ref(), ask, world.store())?;
		let applied = apply(&data_dir, &set);
		carried.run(|| log_key_change(KeyEvent::Created, &label, &scopes, by.as_deref(), ip.0));
		Ok::<_, std::io::Error>((key, applied))
	})
	.await
	.map_err(|_| ApiError::internal())?;
	let (key, applied) = written.map_err(store_error)?;
	// The file holds the key, but the running set did not take it: the
	// answer must not say the key works.
	if let Err(error) = applied {
		tracing::error!(%error, "the API key file was written but the running set did not take it");
		return Err(ApiError::internal());
	}
	let mut view = ApiKeySummary::of(&key).json();
	view["key"] = secret.into();
	let mut response = (StatusCode::CREATED, Json(view)).into_response();
	response
		.headers_mut()
		.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
	Ok(response)
}

/// Make the running server see the file as it is now, without waiting for the
/// watcher: a key revoked is refused at once. A file that cannot be read
/// back is an error: the answer must not say the change is in force.
fn apply(data_dir: &std::path::Path, set: &ApiKeySet) -> std::io::Result<()> {
	set.reload_file(&data_dir.join("api_keys.toml"))
}

/// The answer to a refusal of the store.
fn store_error(error: std::io::Error) -> ApiError {
	use std::io::ErrorKind::*;
	match error.kind() {
		AlreadyExists => ApiError::conflict(error.to_string()),
		QuotaExceeded => ApiError::conflict(error.to_string()),
		ResourceBusy => ApiError::conflict(error.to_string()),
		InvalidInput => ApiError::invalid_input(&error.to_string()),
		PermissionDenied => ApiError::forbidden("the key that asked is no longer valid"),
		NotFound => not_found(),
		_ => {
			tracing::error!(%error, "the API key store failed");
			ApiError::internal()
		}
	}
}

pub async fn revoke(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(label): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let caller = asking(&principal)?;
	let by = principal.key_label().map(str::to_owned);
	let carried = Carried::capture();
	let (data_dir, set) = (state.data_dir().to_path_buf(), Arc::clone(state.api_keys()));
	let world = state.clone();
	let done = tokio::task::spawn_blocking(move || {
		let mut store = ApiKeyStore::open(&data_dir)?;
		let removed = match &caller {
			Some(caller) => {
				store.remove_by(&label, caller, |own, key| reaches(&world, Some(own), key))?
			}
			None => {
				let key = store
					.keys()
					.iter()
					.find(|key| key.label == label)
					.cloned()
					.ok_or_else(|| {
						std::io::Error::new(std::io::ErrorKind::NotFound, "no such API key")
					})?;
				store.remove(&label)?;
				key
			}
		};
		let applied = apply(&data_dir, &set);
		if applied.is_err() {
			// The file no longer holds the key, so the running set must not
			// go on accepting it, even when the file cannot be read back.
			set.forget(&removed.label);
		}
		carried.run(|| {
			log_key_change(
				KeyEvent::Revoked,
				&removed.label,
				display_names(&removed.scopes, &removed.grants),
				by.as_deref(),
				ip.0,
			)
		});
		Ok::<_, std::io::Error>((removed, applied))
	})
	.await
	.map_err(|_| ApiError::internal())?;
	let (removed, applied) = done.map_err(store_error)?;
	// The key is out of the file, but the running set did not take it: the
	// answer must not say the revocation is in force.
	if let Err(error) = applied {
		tracing::error!(%error, "the API key file was written but the running set did not take it");
		return Err(ApiError::internal());
	}
	Ok(Json(serde_json::json!({ "revoked": removed.label })))
}

#[cfg(test)]
mod tests;
