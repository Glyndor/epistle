//! `GET /api/v1/status`.

use axum::extract::State;
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};

#[derive(Serialize)]
pub struct Status {
	version: &'static str,
	domains: usize,
	accounts: usize,
	/// Absent for a key confined to some domains: the queue is shared, and a
	/// count of it would include the other tenants' messages.
	#[serde(skip_serializing_if = "Option::is_none")]
	queue_size: Option<usize>,
}

/// Counters for the server, or, for a key confined to some domains, for the
/// domains and accounts it reaches.
pub async fn get(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Result<Json<Status>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	// The queue is shared, so a count of it would include the other
	// tenants' messages: only an unrestricted key is told the size.
	let queue_size = if principal.is_unrestricted() {
		Some(
			state
				.spool()
				.list()
				.map_err(|_| ApiError::internal())?
				.len(),
		)
	} else {
		None
	};
	Ok(Json(Status {
		version: env!("CARGO_PKG_VERSION"),
		domains: state
			.domains()
			.iter()
			.filter(|domain| principal.admits_domain(domain))
			.count(),
		accounts: state
			.accounts()
			.iter()
			.filter(|account| principal.admits_account(&account.name, &account.addresses))
			.count(),
		queue_size,
	}))
}
