//! `GET /api/v1/domains` and `GET /api/v1/domains/{domain}`: the hosted
//! domains as `epistle domain list --json` and `epistle domain show --json`
//! print them, both read from [`crate::domain::catalog`]. A key confined to
//! some domains sees only those.

use axum::extract::State;
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::Principal;
use crate::api::state::{ApiState, MatchedAuth};
use crate::domain::catalog::DomainRow;

pub(super) mod domain;

#[derive(Serialize)]
pub struct Domains {
	/// Every hosted domain in the caller's scope.
	domains: Vec<String>,
	/// Those of them that are switched off: mail for them is rejected.
	disabled: Vec<String>,
	/// The same domains with their role and alias edges, each the row
	/// `epistle domain list --json` prints for it.
	details: Vec<DomainRow>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Json<Domains> {
	let principal = Principal::for_token(&state, &auth);
	let visible: Vec<String> = state
		.domains()
		.iter()
		.filter(|domain| principal.admits_domain(domain))
		.cloned()
		.collect();
	let disabled = visible
		.iter()
		.filter(|domain| {
			state
				.disabled_domains()
				.iter()
				.any(|off| off.eq_ignore_ascii_case(domain))
		})
		.cloned()
		.collect();
	let details = state
		.domain_catalog()
		.rows()
		.into_iter()
		.filter(|row| principal.admits_domain(&row.domain))
		.collect();
	Json(Domains {
		domains: visible,
		disabled,
		details,
	})
}

#[cfg(test)]
mod tests;
