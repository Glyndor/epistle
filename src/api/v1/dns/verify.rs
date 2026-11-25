//! `GET /api/v1/dns/verify`.

use std::time::Duration;

use axum::extract::{Query, State};
use axum::{Extension, Json};

use super::{Scope, select, too_many};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::dns::verify::{report_json, verify as check};

/// Most hosted domains one check covers: each is a dozen lookups.
pub(super) const MOST_DOMAINS: usize = 20;

/// How long a check may run before the route gives up on it.
pub(super) const DEADLINE: Duration = Duration::from_secs(45);

/// What to tell a caller that finds every place for a check taken.
const BUSY_RETRY_SECS: u64 = 5;

pub async fn verify(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(query): Query<Scope>,
) -> Result<Json<serde_json::Value>, ApiError> {
	let selection = select(&state, &auth, &query)?;
	too_many(selection.domains.len(), MOST_DOMAINS)?;
	// The place is taken before any lookup starts and given back when the
	// check ends, however it ends.
	let Some(_place) = state.try_dns_check() else {
		return Err(ApiError::rate_limited_with_message(
			"DNS checks are already running. Try again shortly.",
			BUSY_RETRY_SECS,
		));
	};
	let lookup = state.dns_lookup().map_err(|error| {
		tracing::error!(%error, "the system resolver cannot be started");
		ApiError::unavailable("The DNS resolver cannot be started.")
	})?;
	let finished = tokio::time::timeout(
		DEADLINE,
		check(
			&selection.config,
			&selection.domains,
			selection.with_host,
			lookup.as_ref(),
		),
	)
	.await
	.map_err(|_| ApiError::timed_out("The DNS check did not finish in time."))?;
	let groups = finished.map_err(|error| {
		tracing::error!(%error, "the DKIM selectors cannot be read");
		ApiError::internal()
	})?;
	Ok(Json(report_json(&groups)))
}
