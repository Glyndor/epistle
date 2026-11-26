//! `DELETE /api/v1/send/{id}`: take back a message the account sent, while
//! the send delay (`[queue.undo_send]`) still holds it.

use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::Serialize;
use uuid::Uuid;

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::storage::undo::{CancelError, Canceller};

#[derive(Serialize)]
pub struct Canceled {
	canceled: Uuid,
}

/// Cancel the held submission `id`. The key must be able to act for the
/// account that sent it: an account-bound key for its own, a key confined to
/// some domains for accounts there, an unconfined key for any. An id that is
/// unknown, that belongs to another account or that this key cannot reach
/// answers the same `404`. A message already handed on answers `409
/// already_sent`: nothing can take it back.
pub async fn cancel(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(id): Path<Uuid>,
) -> Result<Json<Canceled>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let store = state.undo_store().map_err(|_| ApiError::internal())?;
	let not_found = || ApiError::not_found("no such pending message");
	let Some((account, _)) = store.lookup(id).map_err(|_| ApiError::internal())? else {
		// No longer pending: handed on, if the record of its release names an
		// account this key reaches; unknown to this key otherwise.
		let released = store
			.released_account(id)
			.map_err(|_| ApiError::internal())?;
		return Err(match released {
			Some(account) if reaches(&state, &principal, &account) => ApiError::already_sent(),
			_ => not_found(),
		});
	};
	if !reaches(&state, &principal, &account) {
		return Err(not_found());
	}
	match store.cancel_now(id, Canceller::Account(&account)) {
		Ok(()) => {
			tracing::info!(
				account = %crate::log_id::account(&account),
				"a held submission was cancelled by its sender"
			);
			Ok(Json(Canceled { canceled: id }))
		}
		Err(CancelError::AlreadySent) => Err(ApiError::already_sent()),
		Err(CancelError::NotFound) => Err(not_found()),
		Err(CancelError::Io(_)) => Err(ApiError::internal()),
	}
}

/// Whether `principal` may act for `account`: the account must be one the
/// credential reaches by name and by domain, whatever else binds it, and an
/// account-bound credential also needs that account to be live.
fn reaches(state: &ApiState, principal: &Principal, account: &str) -> bool {
	if principal.bound_account().is_some()
		&& !crate::api::account_bound::bound_account_is_live(state, principal)
	{
		return false;
	}
	state
		.accounts()
		.into_iter()
		.find(|view| view.name == account)
		.is_some_and(|view| principal.admits_account(&view.name, &view.addresses))
}
