//! `/api/v1/accounts/{name}/mailboxes`: list mailboxes for an account.

use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::imap::mailbox;
use crate::util::mailbox_path;

/// The mailboxes of an account: every stored name, and the same mailboxes
/// as a tree.
#[derive(Serialize)]
pub struct Mailboxes {
	mailboxes: Vec<String>,
	tree: Vec<TreeEntry>,
}

/// One mailbox in the tree: its id (the stored name), its last level for
/// people, and the id of the nearest mailbox above it, if any.
#[derive(Serialize)]
pub struct TreeEntry {
	id: String,
	name: String,
	parent_id: Option<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
) -> Result<Json<Mailboxes>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let known = state
		.store()
		.account_views()
		.into_iter()
		.find(|(n, _, _)| *n == name);
	// An account outside the caller's domains answers exactly as one that
	// does not exist, so the listing cannot be used to enumerate another
	// tenant's accounts.
	let in_scope =
		known.is_some_and(|(_, addresses, _)| principal.admits_account(&name, &addresses));
	if !in_scope {
		return Err(ApiError::not_found("no such account"));
	}
	let mailboxes = mailbox::list(state.data_dir(), &name);
	let existing: HashSet<&str> = mailboxes.iter().map(String::as_str).collect();
	let tree = mailboxes
		.iter()
		.map(|id| TreeEntry {
			id: id.clone(),
			name: mailbox_path::display_leaf(id),
			parent_id: mailbox_path::nearest_parent(id, |other| existing.contains(other))
				.map(str::to_string),
		})
		.collect();
	Ok(Json(Mailboxes { mailboxes, tree }))
}
