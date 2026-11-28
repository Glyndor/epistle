//! `GET /api/v1/queue` and `DELETE /api/v1/queue/{id}`.

mod cursor;

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::Principal;
use crate::api::audit;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::storage::Budget;

#[cfg(test)]
mod tests;

/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 100;

/// Most queue entries one listing reads. A key confined to some domains only
/// gets its own tenant's entries, so a page may have to skip many others; this
/// bounds the work of a single request, together with the [`Budget`] of the
/// bytes it reads, and `next_cursor` resumes the scan.
const MAX_SCAN: usize = 1000;

#[derive(Deserialize)]
pub struct ListParams {
	limit: Option<usize>,
	/// The `next_cursor` of the page before: the id of an entry the key can
	/// see, or the sealed position the walk stopped at.
	cursor: Option<String>,
}

#[derive(Serialize)]
pub struct QueueEntry {
	id: Uuid,
	reverse_path: String,
	recipients: Vec<String>,
}

#[derive(Serialize)]
pub struct QueuePage {
	entries: Vec<QueueEntry>,
	/// Pass as `cursor` to fetch the next page; absent on the last page.
	#[serde(skip_serializing_if = "Option::is_none")]
	next_cursor: Option<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(params): Query<ListParams>,
) -> Result<Json<QueuePage>, ApiError> {
	let limit = params.limit.unwrap_or(50).min(MAX_LIMIT);
	if limit == 0 {
		return Err(ApiError::field_out_of_range(
			"limit",
			"limit must be at least 1",
		));
	}
	let principal = Principal::for_token(&state, &auth);

	// The cursor names the entry the walk stopped after: the id of an entry
	// the key can see, or the sealed position of one it cannot.
	let anchor = match params.cursor.as_deref() {
		Some(cursor) => Some(cursor::anchor(cursor).ok_or_else(|| {
			ApiError::value_not_allowed("cursor", "the cursor is not one this server issued")
		})?),
		None => None,
	};
	// UUID v7 ids sort chronologically: the page resumes strictly after the
	// anchor, with the oldest entries it may read.
	let listed = state
		.spool()
		.list_after(anchor, MAX_SCAN)
		.map_err(|_| ApiError::internal())?;
	let mut budget = Budget::standard();
	let mut entries = Vec::new();
	// The last entry the walk read, and whether the key reaches it.
	let mut last_read: Option<(Uuid, bool)> = None;
	let mut position = 0;
	while position < listed.ids.len() && entries.len() < limit && !budget.is_spent() {
		let id = listed.ids[position];
		position += 1;
		// The envelope is all a listing needs: no message is read. An entry
		// can vanish between the list and the read (the worker delivered it).
		let envelope = state.spool().load_envelope_within(id, &mut budget);
		let reaches = envelope
			.as_ref()
			.is_ok_and(|envelope| super::queue_access::reaches(&principal, envelope));
		last_read = Some((id, reaches));
		if reaches && let Ok(envelope) = envelope {
			entries.push(QueueEntry {
				id,
				reverse_path: envelope.reverse_path,
				recipients: envelope.recipients,
			});
		}
	}
	let more = position < listed.ids.len() || listed.more;
	let next_cursor = match (more, last_read) {
		(false, _) => None,
		// The walk stopped on an entry the key can see: its id is the cursor,
		// as it always was.
		(true, Some((id, true))) => Some(id.to_string()),
		// The walk stopped on an entry the key cannot see: its id would tell
		// the key that an entry of another tenant waits in the queue, so the
		// position is sealed instead. The next page carries on from there, so
		// the walk still advances and ends.
		(true, Some((id, false))) => Some(cursor::seal(id).ok_or_else(ApiError::internal)?),
		(true, None) => None,
	};
	Ok(Json(QueuePage {
		entries,
		next_cursor,
	}))
}

#[derive(Serialize)]
pub struct Removed {
	removed: Uuid,
}

pub async fn remove(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(client_ip): Extension<ClientIp>,
	Path(id): Path<Uuid>,
) -> Result<Json<Removed>, ApiError> {
	// An entry of another tenant answers like one that is not there.
	let principal = Principal::for_token(&state, &auth);
	match state.spool().load_envelope(id) {
		Ok(envelope) if super::queue_access::reaches(&principal, &envelope) => {}
		_ => return Err(ApiError::not_found("no such queue entry")),
	}
	// The cancellation is recorded, and the entry removed, as one step. What
	// the key may remove is decided on the entry as it is read under the
	// spool's lock, so a hold put between the load above and the removal is
	// the one that counts: a key confined to some domains does not remove mail
	// the operator (or a key outside its reach) holds.
	let by = match principal.confined_domains() {
		Some(domains) => crate::queue::inspect::Holder::Confined(domains.to_vec()),
		None => crate::queue::inspect::Holder::Operator,
	};
	// The label of the key, never the key: the line says who asked, not with
	// what.
	let key = principal.key_label().map(str::to_owned);
	let removed = crate::queue::cancel::remove_if(
		state.spool(),
		&crate::evidence::service::root_of(state.data_dir()),
		(
			state.data_dir(),
			state.delivery_log_days().unwrap_or_default(),
		),
		id,
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs(),
		state.webhook(),
		|fresh| {
			if !super::queue_access::reaches(&principal, fresh) {
				return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
			}
			// A hold someone placed, before the removal or while it was
			// under way; the marker of a removal is no one's hold.
			if fresh.has_real_hold() && !by.may_lift(fresh.held_by.as_deref()) {
				return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
			}
			Ok(())
		},
	)
	.map_err(|error| match error.kind() {
		std::io::ErrorKind::PermissionDenied => ApiError::forbidden(
			"the entry is on hold, and the hold was not put by this key or one inside its domains",
		),
		std::io::ErrorKind::NotFound => ApiError::not_found("no such queue entry"),
		std::io::ErrorKind::ResourceBusy => ApiError::conflict(
			"the entry has evidence outcomes waiting to be written: it stays until they are",
		),
		_ => ApiError::internal(),
	})?;
	// The line is written on the same task that took the entry out, right
	// after it left: there is no await between the removal and the line, so a
	// client that drops the connection cannot take the trace with it.
	audit::log_queue_removed(id, removed.account.as_deref(), key.as_deref(), client_ip.0);
	Ok(Json(Removed { removed: id }))
}
