//! `POST /api/v1/accounts/{name}/addresses` and
//! `DELETE /api/v1/accounts/{name}/addresses/{address}`: what
//! `epistle account address add` and `remove` do, through the same store
//! writes. The caps on addresses per account and on a tenant's accounts are
//! counted there, over the account file as the write reads it.
//!
//! The scope is `manage:write`. A key confined to domains changes the
//! accounts that live entirely inside them, and any other account is the same
//! `404` as one that does not exist. It gives them addresses inside its
//! domains only, with one answer whether the domain is hosted here or not, so
//! a tenant cannot learn which domains the others use. It changes no address of
//! a suspended account: one taken off would be free to give to an account that
//! is not suspended.
//!
//! The key is read again under the account store's lock, of the account as the
//! file holds it there, and a refusal there is the `404`. A change that was
//! written leaves one audit line, made with it on a thread a client that goes
//! away does not stop; a request that wrote nothing leaves none.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};

use super::super::accounts::store_error;
use super::super::scope::account_in_scope;
use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::audit::{AddressEvent, Carried, log_address_change};
use crate::api::authorization::suspension::READDRESSING;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::directory_store::StoreError;
use crate::util::address::normalize;

/// Longest address a request may name: 254 for the address and room for what
/// a malformed one carries, so the store, not this, says what is wrong.
const MAX_ADDRESS: usize = 320;

/// The body of `POST /api/v1/accounts/{name}/addresses`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Add {
	address: String,
}

/// The answer to a refusal of the store. A taken address is the same `409`
/// whoever holds it, and does not name the holder.
fn failure(error: StoreError) -> ApiError {
	match error {
		StoreError::Duplicate(_) => {
			ApiError::conflict("that address is already taken.".to_string())
		}
		other => store_error(other),
	}
}

fn bounded(address: &str) -> Result<(), ApiError> {
	if address.is_empty() || address.len() > MAX_ADDRESS {
		return Err(ApiError::field_out_of_range(
			"address",
			"an address is 1 to 320 characters",
		));
	}
	Ok(())
}

/// The result, the one `epistle account address --json` prints.
fn result(verb: &str, account: &str, address: &str) -> Value {
	crate::cli::json_out::change_object(
		&format!("address {verb}"),
		true,
		json!({ "account": account, "address": address }),
		None,
	)
}

pub async fn add_address(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(name): Path<String>,
	Json(body): Json<Add>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
	bounded(&body.address)?;
	let principal = Principal::for_token(&state, &auth);
	account_in_scope(&state, &principal, &name)?;
	let address = normalize(&body.address);
	if !principal.admits_sender(&address) {
		return Err(ApiError::forbidden(
			"the address is outside the domains of this key.",
		));
	}
	// Said before the write too, so the key learns why. The write asks again.
	if !principal.admits_suspended(state.store().is_disabled(&name)) {
		return Err(ApiError::forbidden(READDRESSING));
	}
	let answer = result("add", &name, &address);
	let event = AddressEvent::Added;
	change(state, auth, &principal, ip, event, name, address).await?;
	Ok((StatusCode::CREATED, Json(answer)))
}

pub async fn remove_address(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path((name, address)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
	bounded(&address)?;
	let principal = Principal::for_token(&state, &auth);
	account_in_scope(&state, &principal, &name)?;
	// Said before the write too, so the key learns why. The write asks again.
	if !principal.admits_suspended(state.store().is_disabled(&name)) {
		return Err(ApiError::forbidden(READDRESSING));
	}
	let address = normalize(&address);
	let answer = result("remove", &name, &address);
	let event = AddressEvent::Removed;
	change(state, auth, &principal, ip, event, name, address).await?;
	Ok(Json(answer))
}

/// Make the change and write its line together, on a thread of its own.
async fn change(
	state: ApiState,
	auth: MatchedAuth,
	principal: &Principal,
	ip: ClientIp,
	event: AddressEvent,
	name: String,
	address: String,
) -> Result<(), ApiError> {
	let carried = Carried::capture();
	let key = principal.key_label().map(str::to_owned);
	tokio::task::spawn_blocking(move || {
		let scope = Scope::ManageWrite;
		match event {
			AddressEvent::Added => state.store().add_address_if(&name, &address, |account| {
				Principal::still_adds_address(&state, &auth, scope, account, &address)
			})?,
			AddressEvent::Removed => {
				state
					.store()
					.remove_address_if(&name, &address, |account| {
						Principal::still_removes_address(&state, &auth, scope, account)
					})?
			}
		}
		carried.run(|| log_address_change(event, &name, &address, key.as_deref(), ip.0));
		Ok::<_, StoreError>(())
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(failure)
}
