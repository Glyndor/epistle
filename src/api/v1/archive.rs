//! `/api/v1/accounts/{name}/archive`: list and restore archived messages.
//!
//! The archive exists only when `[storage] deleted_retention_days` is set to
//! a positive value; otherwise every route here returns `404 not_found` so a
//! client can tell the difference between "the archive is empty" and
//! "retention is off".

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::imap::archive;

/// One entry in the archive listing. `mailbox` is the mailbox the message
/// was in when it was expunged; `deleted_at` is the unix time the archive
/// sidecar was written.
#[derive(Serialize)]
pub struct ArchiveEntry {
	id: Uuid,
	mailbox: String,
	deleted_at: u64,
}

/// The archive listing payload.
#[derive(Serialize)]
pub struct ArchiveListing {
	entries: Vec<ArchiveEntry>,
}

/// `GET /api/v1/accounts/{name}/archive`: every archived message for the
/// account, oldest first. Returns `404` when the archive directory does not
/// exist (retention is off, or the account has never received an expunge).
pub async fn list(
	State(state): State<ApiState>,
	Path(name): Path<String>,
) -> Result<Json<ArchiveListing>, ApiError> {
	if !account_known(&state, &name) {
		return Err(ApiError::not_found("no such account"));
	}
	let account_root = state.data_dir().join("accounts").join(&name);
	let entries = archive::list(&account_root)
		.map_err(|error| ApiError::not_found(&format!("archive not available: {error}")))?;
	let entries = entries
		.into_iter()
		.map(|entry| ArchiveEntry {
			id: entry.id,
			mailbox: entry.mailbox,
			deleted_at: entry.deleted_at,
		})
		.collect();
	Ok(Json(ArchiveListing { entries }))
}

/// The response body for `POST .../archive/{id}/restore`.
#[derive(Serialize)]
pub struct Restored {
	id: Uuid,
	restored_to: String,
}

/// `POST /api/v1/accounts/{name}/archive/{id}/restore`: re-append the
/// archived message to its original mailbox, or to `INBOX` when that
/// mailbox no longer exists, then remove it from the archive.
pub async fn restore(
	State(state): State<ApiState>,
	Path((name, id)): Path<(String, Uuid)>,
) -> Result<Json<Restored>, ApiError> {
	if !account_known(&state, &name) {
		return Err(ApiError::not_found("no such account"));
	}
	let restored_to = archive::restore(state.data_dir(), &name, id, state.crypto())
		.map_err(|error| ApiError::not_found(&format!("cannot restore: {error}")))?;
	Ok(Json(Restored { id, restored_to }))
}

/// Whether `name` is a known account (either configured or dynamic).
fn account_known(state: &ApiState, name: &str) -> bool {
	state
		.store()
		.account_views()
		.into_iter()
		.any(|(n, _, _)| n == name)
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
