//! `GET /api/v1/status`.

use axum::extract::State;
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::domain_scope::DomainScope;
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
	let scope = state.domain_scope(&auth);
	let queue_size = match scope {
		DomainScope::All => Some(
			state
				.spool()
				.list()
				.map_err(|_| ApiError::internal())?
				.len(),
		),
		DomainScope::Only(_) => None,
	};
	Ok(Json(Status {
		version: env!("CARGO_PKG_VERSION"),
		domains: state
			.domains()
			.iter()
			.filter(|domain| scope.admits_domain(domain))
			.count(),
		accounts: state
			.accounts()
			.iter()
			.filter(|account| scope.admits_account(account.addresses.iter().map(String::as_str)))
			.count(),
		queue_size,
	}))
}
