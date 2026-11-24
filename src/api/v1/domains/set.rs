//! `PUT /api/v1/domains/{domain}`: one atomic role/limits change. The limits
//! need an unconfined key; the role does not.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Deserializer};

use super::change::{self, Changed};
use crate::api::audit::DomainEvent;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::api::{Principal, error::ApiError};
use crate::domain::state::{Change, StoredRole};

/// A missing field leaves it alone; an explicit null clears the override.
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetDomain {
	#[serde(default)]
	role: Option<StoredRole>,
	#[serde(default, deserialize_with = "present")]
	quota: Option<Option<u64>>,
	#[serde(default, deserialize_with = "present")]
	submission_rate: Option<Option<u32>>,
}

pub async fn set(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(raw): Path<String>,
	Json(request): Json<SetDomain>,
) -> Result<Json<Changed>, ApiError> {
	let domain = change::canonical("domain", &raw)?;
	let principal = Principal::for_token(&state, &auth);
	change::in_scope(&principal, &domain)?;
	// Limits belong to the operator: a key confined to some domains may
	// change the role of its own domains, never the caps on them.
	if request.quota.is_some() || request.submission_rate.is_some() {
		crate::api::v1::scope::require_unconfined(&principal, "Changing a domain's limits")?;
	}
	let done = change::commit(
		&state,
		Change::Set {
			name: domain.clone(),
			role: request.role,
			quota: request.quota,
			submission_rate: request.submission_rate,
		},
		None,
		change::Trail::new(DomainEvent::Updated, &domain, ip),
	)
	.await?;
	Ok(Json(Changed::of(&done, domain)))
}
