//! `/api/v1/accounts/{name}/mailboxes`: list mailboxes for an account.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::imap::mailbox;

#[derive(Serialize)]
pub struct Mailboxes {
	mailboxes: Vec<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
) -> Result<Json<Mailboxes>, ApiError> {
	let scope = state.domain_scope(&auth);
	let known = state
		.store()
		.account_views()
		.into_iter()
		.find(|(n, _, _)| *n == name);
	// An account outside the caller's domains answers exactly as one that
	// does not exist, so the listing cannot be used to enumerate another
	// tenant's accounts.
	let in_scope = known.is_some_and(|(_, addresses, _)| {
		scope.admits_account(addresses.iter().map(String::as_str))
	});
	if !in_scope {
		return Err(ApiError::not_found("no such account"));
	}
	let mailboxes = mailbox::list(state.data_dir(), &name);
	Ok(Json(Mailboxes { mailboxes }))
}
