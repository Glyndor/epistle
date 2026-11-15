//! Enable/disable preserve the stored role and follow the CLI policy.

use super::change::{self, Changed};
use crate::api::audit::DomainEvent;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::api::{Principal, error::ApiError};
use crate::domain::state::Change;
use axum::extract::{Path, State};
use axum::{Extension, Json};

async fn switch(
	state: ApiState,
	auth: MatchedAuth,
	ip: ClientIp,
	raw: String,
	enabled: bool,
) -> Result<Json<Changed>, ApiError> {
	let domain = change::canonical("domain", &raw)?;
	change::in_scope(&Principal::for_token(&state, &auth), &domain)?;
	let done = change::commit(&state, Change::SetEnabled { name: raw, enabled }, None).await?;
	change::audit(
		&done,
		if enabled {
			DomainEvent::Enabled
		} else {
			DomainEvent::Disabled
		},
		&domain,
		ip,
	);
	Ok(Json(Changed::of(&done, domain)))
}

pub async fn enable(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(domain): Path<String>,
) -> Result<Json<Changed>, ApiError> {
	switch(state, auth, ip, domain, true).await
}

pub async fn disable(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(domain): Path<String>,
) -> Result<Json<Changed>, ApiError> {
	switch(state, auth, ip, domain, false).await
}
