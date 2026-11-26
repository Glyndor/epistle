//! `GET /api/v1/queue` and `DELETE /api/v1/queue/{id}`.

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};

/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 100;

/// Most queue entries one listing reads. A key confined to some domains only
/// gets its own tenant's entries, so a page may have to skip many others; this
/// bounds the work of a single request, and `next_cursor` resumes the scan.
const MAX_SCAN: usize = 1000;

#[derive(Deserialize)]
pub struct ListParams {
	limit: Option<usize>,
	cursor: Option<Uuid>,
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
	next_cursor: Option<Uuid>,
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

	let ids = state.spool().list().map_err(|_| ApiError::internal())?;
	let mut position = match params.cursor {
		// UUID v7 ids sort chronologically: resume strictly after cursor.
		Some(cursor) => ids.partition_point(|id| *id <= cursor),
		None => 0,
	};
	let mut entries = Vec::new();
	let mut last_read = None;
	let mut scanned = 0;
	while position < ids.len() && entries.len() < limit && scanned < MAX_SCAN {
		let id = ids[position];
		position += 1;
		scanned += 1;
		last_read = Some(id);
		// An entry can vanish between list and load (worker delivered it).
		if let Ok(entry) = state.spool().load(id)
			&& super::queue_access::reaches(&principal, &entry.envelope)
		{
			entries.push(QueueEntry {
				id,
				reverse_path: entry.envelope.reverse_path,
				recipients: entry.envelope.recipients,
			});
		}
	}
	let next_cursor = if position < ids.len() {
		last_read
	} else {
		None
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
	Path(id): Path<Uuid>,
) -> Result<Json<Removed>, ApiError> {
	// An entry of another tenant answers like one that is not there.
	let principal = Principal::for_token(&state, &auth);
	match state.spool().load(id) {
		Ok(entry) if super::queue_access::reaches(&principal, &entry.envelope) => {}
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
	crate::queue::cancel::remove_if(
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
	Ok(Json(Removed { removed: id }))
}
