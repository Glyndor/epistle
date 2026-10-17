//! `GET /api/v1/domains`.

use axum::extract::State;
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::state::{ApiState, MatchedAuth};

#[derive(Serialize)]
pub struct Domains {
	/// Every hosted domain in the caller's scope.
	domains: Vec<String>,
	/// Those of them that are switched off: mail for them is rejected.
	disabled: Vec<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Json<Domains> {
	let scope = state.domain_scope(&auth);
	let visible: Vec<String> = state
		.domains()
		.iter()
		.filter(|domain| scope.admits_domain(domain))
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
	Json(Domains {
		domains: visible,
		disabled,
	})
}
