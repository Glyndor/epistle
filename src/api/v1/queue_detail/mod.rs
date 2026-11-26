//! `GET /api/v1/queue/{id}`, `POST /api/v1/queue/{id}/{retry,hold,release}`
//! and `GET /api/v1/queue/destinations`: one entry as `epistle queue show`
//! shows it, the three changes `epistle queue retry`, `hold` and `release`
//! make, and the destinations the queue holds off. The code is the
//! command's ([`crate::queue::inspect`]).
//!
//! An entry belongs to the tenant of its sender: a key confined to some
//! domains reaches the entries whose sender is inside them, and gets one
//! answer, `404 no such queue entry`, for one that is not there and one that is
//! not its own. Showing is `read`, changing is `write`, as for removing an
//! entry. The destinations are shared by every tenant, so they are for a key
//! with no confinement.

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::Principal;
use crate::api::audit::{Carried, QueueEvent, log_queue_change};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::queue::inspect::{self, Header, Holder, Refused, Steer};

/// Most destinations one answer lists.
const MOST_DESTINATIONS: usize = 1000;

/// The one answer for an entry that is not there and one that is not the
/// key's.
fn not_found() -> ApiError {
	ApiError::not_found("no such queue entry")
}

/// The entry `id`, when the key reaches it.
fn reachable(
	state: &ApiState,
	principal: &Principal,
	id: Uuid,
) -> Result<crate::storage::Envelope, ApiError> {
	match state.spool().load_envelope(id) {
		Ok(envelope) if super::queue_access::reaches(principal, &envelope) => Ok(envelope),
		_ => Err(not_found()),
	}
}

/// The query of `GET /api/v1/queue/{id}`.
#[derive(Debug, Deserialize)]
pub struct ShowQuery {
	/// Also return the header fields of the message.
	#[serde(default)]
	headers: bool,
}

/// An entry with, when asked, the headers of its message.
#[derive(Debug, Serialize)]
pub struct Shown {
	/// What `epistle queue show --json` prints.
	#[serde(flatten)]
	entry: serde_json::Value,
	#[serde(skip_serializing_if = "Option::is_none")]
	headers: Option<Vec<Header>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	headers_truncated: Option<bool>,
}

pub async fn show(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(id): Path<Uuid>,
	Query(query): Query<ShowQuery>,
) -> Result<Json<Shown>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let envelope = reachable(&state, &principal, id)?;
	let entry = inspect::show_view(&envelope);
	if !query.headers {
		return Ok(Json(Shown {
			entry,
			headers: None,
			headers_truncated: None,
		}));
	}
	let held = state.clone();
	let message = tokio::task::spawn_blocking(move || held.spool().load(id))
		.await
		.map_err(|_| ApiError::internal())?;
	// The worker may have delivered it since the envelope was read.
	let message = match message {
		Ok(message) => message,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
		Err(error) => {
			tracing::error!(%error, "queue entry cannot be read");
			return Err(ApiError::internal());
		}
	};
	let (headers, truncated) = inspect::headers_of(&message.data);
	Ok(Json(Shown {
		entry,
		headers: Some(headers),
		headers_truncated: Some(truncated),
	}))
}

/// The answer to a change.
#[derive(Debug, Serialize)]
pub struct Steered {
	/// False when the entry already was as the change leaves it.
	changed: bool,
	id: Uuid,
	held: bool,
}

async fn steer(
	state: ApiState,
	auth: MatchedAuth,
	ip: ClientIp,
	id: Uuid,
	change: Steer,
) -> Result<Json<Steered>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	reachable(&state, &principal, id)?;
	let carried = Carried::capture();
	let key = principal.key_label().map(str::to_owned);
	let by = match principal.confined_domains() {
		Some(domains) => Holder::Confined(domains.to_vec()),
		None => Holder::Operator,
	};
	let event = match change {
		Steer::Retry => QueueEvent::Retried,
		Steer::Hold => QueueEvent::Held,
		Steer::Release => QueueEvent::Released,
	};
	// The change and its line are made on one blocking thread, which a client
	// that goes away does not cancel.
	let done = tokio::task::spawn_blocking(move || {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_or(0, |elapsed| elapsed.as_secs());
		let done = inspect::steer(state.spool(), id, change, &by, now)?;
		if done.changed && done.refused.is_none() {
			carried.run(|| log_queue_change(event, id, key.as_deref(), ip.0));
		}
		Ok::<_, std::io::Error>(done)
	})
	.await
	.map_err(|_| ApiError::internal())?;
	match done {
		Ok(done) if done.refused == Some(Refused::Cancelling) => Err(ApiError::conflict(
			"the entry is being removed and stays on hold until it is",
		)),
		Ok(done) if done.refused == Some(Refused::HeldByOther) => Err(ApiError::forbidden(
			"the hold was not put by this key or one inside its domains",
		)),
		Ok(done) => Ok(Json(Steered {
			changed: done.changed,
			id,
			held: done.envelope.held.is_some(),
		})),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(not_found()),
		Err(error) => {
			tracing::error!(%error, "queue entry cannot be changed");
			Err(ApiError::internal())
		}
	}
}

pub async fn retry(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(id): Path<Uuid>,
) -> Result<Json<Steered>, ApiError> {
	steer(state, auth, ip, id, Steer::Retry).await
}

pub async fn hold(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(id): Path<Uuid>,
) -> Result<Json<Steered>, ApiError> {
	steer(state, auth, ip, id, Steer::Hold).await
}

pub async fn release(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(id): Path<Uuid>,
) -> Result<Json<Steered>, ApiError> {
	steer(state, auth, ip, id, Steer::Release).await
}

/// The destinations the queue holds off.
#[derive(Debug, Serialize)]
pub struct Destinations {
	/// The rows `epistle queue destinations --json` prints.
	destinations: Vec<serde_json::Value>,
	/// True when there were more than the answer lists.
	truncated: bool,
}

pub async fn destinations(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Result<Json<Destinations>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	super::scope::require_unconfined(&principal, "the destinations the queue holds off")?;
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs());
	let mut rows =
		tokio::task::spawn_blocking(move || inspect::destination_rows(state.spool(), now))
			.await
			.map_err(|_| ApiError::internal())?
			.map_err(|error| {
				tracing::error!(%error, "the destinations cannot be read");
				ApiError::internal()
			})?;
	let truncated = rows.len() > MOST_DESTINATIONS;
	rows.truncate(MOST_DESTINATIONS);
	Ok(Json(Destinations {
		destinations: rows,
		truncated,
	}))
}

#[cfg(test)]
mod tests;
