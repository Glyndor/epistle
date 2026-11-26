//! `GET /api/v1/health` and `GET /api/v1/health/{area}`: what `epistle status
//! --json` and `epistle check <area> --json` print, from the code the
//! commands run ([`crate::cli::status`]). The areas stay where they are,
//! because they read the host, the stack and the network through the command
//! line's own helpers; the routes call the one entry the commands also use.
//!
//! The scope is `health`, and only `health`: not `read`. The answer names
//! the listeners, the certificate, the disk, the keys and the state of the
//! stack, which belong to the server and not to a tenant, so a key confined
//! to domains is refused (`403`), as is one bound to an account. The areas
//! run against the configuration the server has now, with the state files
//! laid over it.
//!
//! The answer is `200` whatever the areas find: a failing area is in the
//! body, as it is in the command's output, and the command's exit code has no
//! HTTP counterpart. At most two runs are in progress on a server (the third
//! is a `429` with `Retry-After`), and every area is cut off at the deadline
//! the command uses.

use axum::extract::{Path, State};
use axum::{Extension, Json};

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::cli::status::{CheckArea, area_named, run_json};

/// What to tell a caller that finds every place for a run taken.
const BUSY_RETRY_SECS: u64 = 5;

async fn run(
	state: ApiState,
	auth: MatchedAuth,
	areas: Result<Vec<CheckArea>, ApiError>,
) -> Result<Json<serde_json::Value>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	super::scope::require_unconfined(&principal, "the health of the server")?;
	let areas = areas?;
	let config = state
		.live_domains()
		.map(|live| live.current())
		.ok_or_else(ApiError::internal)?;
	// The place is taken before any check starts. It belongs to the run, not
	// to this request: the run is a task of its own that keeps the place
	// until the last thing it started has ended, so a client that goes away
	// neither stops it nor frees the place while it still works.
	let Some(hold) = state.health_hold() else {
		return Err(ApiError::rate_limited_with_message(
			"Health checks are already running. Try again shortly.",
			BUSY_RETRY_SECS,
		));
	};
	let path = state.config_path().unwrap_or_default();
	#[cfg(test)]
	let alive = state.health_run_alive();
	let run = tokio::spawn(async move {
		#[cfg(test)]
		let _alive = alive;
		run_json(path, (*config).clone(), &areas, hold).await
	});
	let report = run.await.map_err(|_| ApiError::internal())?;
	Ok(Json(report))
}

pub async fn all(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Result<Json<serde_json::Value>, ApiError> {
	let areas = Ok(state.health_areas());
	run(state, auth, areas).await
}

pub async fn one(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
	let areas = area_named(&name)
		.map(|area| vec![area])
		.ok_or_else(|| ApiError::not_found("no such area"));
	run(state, auth, areas).await
}

#[cfg(test)]
mod tests;
