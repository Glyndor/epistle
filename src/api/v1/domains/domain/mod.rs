//! `GET /api/v1/domains/{domain}`: one hosted domain, the object `epistle
//! domain show <domain> --json` prints for the same name.

use axum::extract::{Path, State};
use axum::{Extension, Json};

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::domain::catalog::DomainView;

/// The answer for a domain that is not hosted, and for one outside the
/// key's domains: one answer, so the status cannot tell a confined key which
/// other domains the server hosts.
fn not_hosted() -> ApiError {
	ApiError::not_found("no such domain")
}

pub async fn get(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(domain): Path<String>,
) -> Result<Json<DomainView>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	if !principal.admits_domain(&domain) {
		return Err(not_hosted());
	}
	state
		.domain_catalog()
		.view(&domain)
		.map(Json)
		.ok_or_else(not_hosted)
}
