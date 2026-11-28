//! `POST /api/v1/accounts/{name}/disable` and
//! `POST /api/v1/accounts/{name}/enable`: what `epistle account disable` and
//! `enable` do, through the same store write. A suspended account stops
//! authenticating, with the answer an unknown login gets, and keeps its mail.
//!
//! The scope is `manage:write`. A key confined to domains may already delete
//! the active accounts inside them, so it suspends those, the lesser act.
//! Resuming is for a key that is not confined: an account the operator
//! suspended, for abuse say, is not for a tenant's key to bring back.
//!
//! The key is read again under the account store's lock, and the audit line is
//! decided by the state the account had there: a request that found it already
//! in the state it asks for writes none.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde_json::{Value, json};

use super::super::accounts::store_error;
use super::super::scope::account_in_scope;
use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::audit::{Carried, SuspensionEvent, log_suspension_change};
use crate::api::authorization::suspension::RESUMING;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};

/// Suspend the account `name`.
pub async fn disable(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	account_in_scope(&state, &principal, &name)?;
	change(state, auth, &principal, ip, name, true).await
}

/// Resume the account `name`.
pub async fn enable(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	// Refused before the account is looked at, the same way whatever the
	// name, so a confined key learns nothing of which accounts exist.
	if !principal.admits_suspended(true) {
		return Err(ApiError::forbidden(RESUMING));
	}
	change(state, auth, &principal, ip, name, false).await
}

/// Write the change and its audit line together, on a thread a client that
/// goes away does not stop.
async fn change(
	state: ApiState,
	auth: MatchedAuth,
	principal: &Principal,
	ip: ClientIp,
	name: String,
	disabled: bool,
) -> Result<Json<Value>, ApiError> {
	let key = principal.key_label().map(str::to_owned);
	let carried = Carried::capture();
	let account = name.clone();
	let changed = tokio::task::spawn_blocking(move || {
		let previous = state
			.store()
			.set_disabled_if(&account, disabled, |stored| {
				if disabled {
					Principal::still_reaches_account(
						&state,
						&auth,
						Scope::ManageWrite,
						&stored.name,
						&stored.addresses,
					)
				} else {
					Principal::still_unrestricted(&state, &auth, Scope::ManageWrite)
				}
			})?;
		let changed = previous != disabled;
		if changed {
			let event = if disabled {
				SuspensionEvent::Disabled
			} else {
				SuspensionEvent::Enabled
			};
			carried.run(|| log_suspension_change(event, &account, key.as_deref(), ip.0));
		}
		Ok(changed)
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(store_error)?;
	Ok(Json(crate::cli::json_out::change_object(
		if disabled { "disable" } else { "enable" },
		changed,
		json!({ "account": name, "disabled": disabled }),
		None,
	)))
}
