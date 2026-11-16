//! `GET /api/v1/events`.

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::sse::{KeepAlive, Sse};
use axum::response::{IntoResponse, Response};

use super::stream::{Events, ServerSlot};
use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::jmap::caller_slots::{CallerSlot, Work};
use crate::api::state::{ApiState, MatchedAuth};

/// Seconds a refused client is told to wait before it tries to open a stream.
const RETRY_AFTER: u64 = 5;

/// Open the event stream. The bearer middleware already required the `read`
/// scope for this `GET`, and refuses a key bound to one account.
pub async fn get(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	headers: HeaderMap,
) -> Result<Response, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let Some(owner) = crate::api::jmap::push_subscription::owner_of(&state, &principal) else {
		return Err(ApiError::forbidden(
			"This credential has no caller identity.",
		));
	};
	let limits = *state.events().limits();
	let Some(per_key) = CallerSlot::take_for(&state, &owner, Work::AdminEvents, limits.per_key)
	else {
		return Err(ApiError::rate_limited_with_message(
			"Too many open event streams for this key.",
			RETRY_AFTER,
		));
	};
	let Some(per_server) = ServerSlot::take(&state) else {
		return Err(ApiError::rate_limited_with_message(
			"Too many open event streams on this server.",
			RETRY_AFTER,
		));
	};
	state.ensure_sampler();
	let hub = state.events();
	let start = match headers
		.get("last-event-id")
		.map(|value| value.to_str().ok().and_then(|id| hub.resume_from(id)))
	{
		// Replay what the ring still holds after the id the client last saw.
		Some(Some(cursor)) => (cursor, false),
		// An id this server cannot replay from: tell the client to refetch.
		Some(None) => (hub.head(), true),
		None => (hub.head(), false),
	};
	let events = Events::open(state.clone(), auth, principal, start, (per_key, per_server));
	let mut response = Sse::new(events)
		.keep_alive(
			KeepAlive::new()
				.interval(limits.heartbeat)
				.text("heartbeat"),
		)
		.into_response();
	// A proxy in front must not hold the stream back to batch it.
	response.headers_mut().insert(
		HeaderName::from_static("x-accel-buffering"),
		HeaderValue::from_static("no"),
	);
	Ok(response)
}
