//! `GET /api/v1/domains`.

use axum::extract::State;
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::state::{ApiState, MatchedAuth};

#[derive(Serialize)]
pub struct Domains {
	domains: Vec<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Json<Domains> {
	let scope = state.domain_scope(&auth);
	Json(Domains {
		domains: state
			.domains()
			.iter()
			.filter(|domain| scope.admits_domain(domain))
			.cloned()
			.collect(),
	})
}
