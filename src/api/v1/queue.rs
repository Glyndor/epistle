//! `GET /api/v1/queue` and `DELETE /api/v1/queue/{id}`.

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
		return Err(ApiError::invalid_input("limit must be at least 1"));
	}
	let scope = state.domain_scope(&auth);

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
			&& scope.admits_account(std::iter::once(entry.envelope.reverse_path.as_str()))
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
	let scope = state.domain_scope(&auth);
	match state.spool().load(id) {
		Ok(entry)
			if scope.admits_account(std::iter::once(entry.envelope.reverse_path.as_str())) => {}
		_ => return Err(ApiError::not_found("no such queue entry")),
	}
	// The cancellation is recorded, and the entry removed, as one step.
	crate::queue::cancel::remove(
		state.spool(),
		&crate::evidence::service::root_of(state.data_dir()),
		state.data_dir(),
		state.delivery_log_days().unwrap_or_default(),
		id,
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs(),
		state.webhook(),
	)
	.map_err(|error| match error.kind() {
		std::io::ErrorKind::NotFound => ApiError::not_found("no such queue entry"),
		std::io::ErrorKind::ResourceBusy => ApiError::conflict(
			"the entry has evidence outcomes waiting to be written: it stays until they are",
		),
		_ => ApiError::internal(),
	})?;
	Ok(Json(Removed { removed: id }))
}
