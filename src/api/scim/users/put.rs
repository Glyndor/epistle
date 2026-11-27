//! `PUT /Users/{id}`: replace what SCIM models of an account.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};

use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::scim::error::ScimError;
use crate::api::scim::types::User;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::directory_store::{DynamicAccount, NewPassword};

use super::audit::Changes;
use super::{
	check_password, derive_scram, hash_password, lookup, lookup_in_scope, render_user,
	require_addresses_in_scope, resolve_addresses, scim_resource, store_to_scim,
};

/// `PUT /Users/{id}` — replace the account. We refuse to change `userName`
/// (renames are not supported; see the module doc). Otherwise we honour
/// `active`, `emails`, and the optional `password` extension. Returns 200
/// with the rendered resource.
pub async fn put_user(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(client_ip): Extension<ClientIp>,
	Path(id): Path<String>,
	Json(body): Json<User>,
) -> Result<impl IntoResponse, ScimError> {
	let principal = Principal::for_token(&state, &auth);
	let existing = lookup_in_scope(&state, &principal, &id)?;
	if crate::directory_store::account_name(&body.user_name) != id {
		return Err(ScimError::invalid(
			"userName cannot be changed via PUT; use DELETE then POST",
		));
	}

	// The new addresses are checked before anything is written, so a refused
	// replace leaves the password as it was.
	let addresses = resolve_addresses(&body.emails, &existing.addresses)?;
	require_addresses_in_scope(&principal, &addresses)?;
	state
		.tenant_limits()
		.check_account_move(state.store(), &existing.addresses, &addresses)
		.map_err(ScimError::conflict)?;
	let new_password = match body.password.as_deref() {
		Some(plain) => {
			check_password(plain)?;
			Some(NewPassword {
				hash: hash_password(plain, state.store())?,
				scram: derive_scram(plain, state.store())?,
			})
		}
		None => None,
	};
	// The replacement is made under the store's lock, from the account as it
	// is then. What SCIM does not model (quota, forwards, catch-all, the
	// `Sent` copy, the send and receive switches, the allowed protocols) stays
	// as it is, and so do the addresses when the request names none. The key
	// is read again there too, and asked about the account as it is and as it
	// would become.
	let password_sent = new_password.is_some();
	let disabled = !body.active;
	let previous = state
		.store()
		.replace_account_if(&id, new_password, |current| {
			let addresses = if body.emails.is_empty() {
				current.addresses.clone()
			} else {
				addresses
			};
			let reaches = |addresses: &[String]| {
				Principal::still_reaches_account(
					&state,
					&auth,
					Scope::Scim,
					&current.name,
					addresses,
				)
			};
			(reaches(&current.addresses) && reaches(&addresses)).then(|| DynamicAccount {
				addresses,
				disabled,
				display_name: body.display_name.clone(),
				..current.clone()
			})
		})
		.map_err(store_to_scim)?;
	// The account is written: the line of every change it made follows, on
	// this task and before anything else can be awaited. The password is a
	// change whenever it is sent: the stored verifier, its salt and the SCRAM
	// credentials are replaced, and the account's outstanding credentials are
	// reset. The state is a change only when the write found another one.
	let mut changes = Changes::new(&id, principal.key_label(), client_ip.0);
	if password_sent {
		changes.password();
	}
	changes.state(previous.disabled, disabled);
	changes.write();
	let stored = lookup(&state, &id)?;
	Ok(scim_resource(StatusCode::OK, render_user(&stored)))
}
