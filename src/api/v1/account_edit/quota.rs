//! `PUT` and `DELETE /api/v1/accounts/{name}/quota`: what `epistle account
//! quota` does, through the same size parser and the same store call.
//!
//! A quota is room on the server's disk, so the key that sets one is confined
//! to no account and no domain: a tenant's key could otherwise give its
//! accounts any amount, or put them back on a default that is larger than what
//! they have. A confined key gets one answer (`403`) whatever the account, so
//! it learns nothing of which accounts exist.
//!
//! The key is asked when the request arrives and again under the account
//! store's lock, where the write is made: a key revoked, expired, narrowed or
//! limited to another network while the request waited writes nothing, and the
//! answer is the `404` of an account that does not exist. The change and its
//! audit line are made on one thread, which a client that goes away does not
//! stop.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::audit::{Carried, QuotaEvent, log_quota_change};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::directory_store::StoreError;
use crate::util::quota_size::parse_quota_size;

/// Longest size a request may write: the largest quota in kibibytes is
/// seventeen characters.
const MAX_SIZE: usize = 32;

/// The body of `PUT /api/v1/accounts/{name}/quota`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Set {
	/// A size as the command takes it: `500M`, `10G`, `1T`, or `none` for the
	/// server default.
	quota: String,
}

/// The quota a request names. An account with a quota of zero takes no mail at
/// all, which the command allows an operator to do and a request may not.
fn size_of(raw: &str) -> Result<Option<u64>, ApiError> {
	if raw.len() > MAX_SIZE {
		return Err(ApiError::field_out_of_range(
			"quota",
			"a size is a number and a unit",
		));
	}
	match parse_quota_size(raw) {
		Ok(Some(0)) => Err(ApiError::field_out_of_range(
			"quota",
			"a quota of zero would refuse all mail; clear the quota to use the default",
		)),
		Ok(size) => Ok(size),
		Err(message) => Err(ApiError::invalid_input(&message)),
	}
}

/// Only a key that reaches every domain sets a quota, and every other key is
/// refused before the size or the account is looked at.
fn allowed(principal: &Principal) -> Result<(), ApiError> {
	if principal.is_unrestricted() {
		return Ok(());
	}
	Err(ApiError::forbidden(
		"a quota is set by a key that is not confined to an account or some domains.",
	))
}

pub async fn set_quota(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(name): Path<String>,
	Json(body): Json<Set>,
) -> Result<Json<Value>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	allowed(&principal)?;
	let size = size_of(&body.quota)?;
	change(state, auth, &principal, ip, name, size).await
}

pub async fn clear_quota(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	allowed(&principal)?;
	change(state, auth, &principal, ip, name, None).await
}

/// Make the change and write its line together, on a thread of its own.
async fn change(
	state: ApiState,
	auth: MatchedAuth,
	principal: &Principal,
	ip: ClientIp,
	name: String,
	size: Option<u64>,
) -> Result<Json<Value>, ApiError> {
	let carried = Carried::capture();
	let key = principal.key_label().map(str::to_owned);
	let account = name.clone();
	tokio::task::spawn_blocking(move || {
		state.store().set_quota_bytes_if(&account, size, || {
			Principal::still_unrestricted(&state, &auth, Scope::ManageWrite)
		})?;
		let event = if size.is_some() {
			QuotaEvent::Set
		} else {
			QuotaEvent::Cleared
		};
		carried.run(|| log_quota_change(event, &account, size, key.as_deref(), ip.0));
		Ok::<_, StoreError>(())
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(super::super::accounts::store_error)?;
	Ok(Json(crate::cli::json_out::change_object(
		"quota",
		true,
		json!({ "account": name, "quota_bytes": size }),
		None,
	)))
}
