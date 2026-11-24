//! Alias routes check both names and the fresh target of a removed alias.

use super::change::{self, Changed};
use crate::api::audit::DomainEvent;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::api::{Principal, error::ApiError};
use crate::domain::state::Change;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddAlias {
	alias: String,
}

fn names(
	state: &ApiState,
	auth: &MatchedAuth,
	domain: &str,
	alias: &str,
) -> Result<(String, String), ApiError> {
	let domain = change::canonical("domain alias target", domain)?;
	let alias = change::canonical("domain alias", alias)?;
	let principal = Principal::for_token(state, auth);
	change::in_scope(&principal, &domain)?;
	change::in_scope(&principal, &alias)?;
	Ok((domain, alias))
}

pub async fn add(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(raw_domain): Path<String>,
	Json(request): Json<AddAlias>,
) -> Result<(StatusCode, Json<Changed>), ApiError> {
	let (domain, alias) = names(&state, &auth, &raw_domain, &request.alias)?;
	let done = change::commit(
		&state,
		Change::AliasAdd {
			alias: request.alias,
			target: raw_domain,
		},
		None,
		change::Trail::new(DomainEvent::AliasAdded, &alias, ip),
	)
	.await?;
	Ok((StatusCode::CREATED, Json(Changed::of(&done, domain))))
}

pub async fn remove(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path((raw_domain, raw_alias)): Path<(String, String)>,
) -> Result<Json<Changed>, ApiError> {
	let (domain, alias) = names(&state, &auth, &raw_domain, &raw_alias)?;
	let done = change::commit(
		&state,
		Change::AliasRemove { alias: raw_alias },
		Some(domain.clone()),
		change::Trail::new(DomainEvent::AliasRemoved, &alias, ip),
	)
	.await?;
	Ok(Json(Changed::of(&done, domain)))
}
