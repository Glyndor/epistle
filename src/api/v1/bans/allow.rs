//! `GET`, `POST` and `DELETE` on `/api/v1/bans/allow`: the addresses and
//! networks that are never banned and never counted.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use super::{Trail, caller, cidr_of, detached, refusal, store};
use crate::antispam::bans::operator::{self as admin, Limits};
use crate::api::audit::BanEvent;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};

/// The allow list.
#[derive(Debug, Serialize)]
pub struct Allowed {
	/// The blocks, canonical and sorted: what `epistle ban allow list --json`
	/// prints.
	allow: Vec<String>,
}

pub async fn allow_list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Result<Json<Allowed>, ApiError> {
	caller(&state, &auth)?;
	let allow = store(&state)?
		.allow_list()
		.await
		.map_err(|error| refusal(error.into()))?;
	Ok(Json(Allowed { allow }))
}

/// The body of `POST /api/v1/bans/allow`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
	/// An address or a network.
	cidr: String,
}

/// The answer to adding or removing a block.
#[derive(Debug, Serialize)]
pub struct AllowChanged {
	/// False when the block was already on the list.
	changed: bool,
	cidr: String,
}

pub async fn allow_add(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Json(request): Json<Allow>,
) -> Result<(StatusCode, Json<AllowChanged>), ApiError> {
	let principal = caller(&state, &auth)?;
	let cidr = cidr_of(&request.cidr)?;
	let (store, trail) = (store(&state)?, Trail::new(&principal, ip));
	let added = detached(async move {
		let added = admin::allow(&*store, cidr, Limits::api()).await?;
		if added {
			trail.log(BanEvent::Allowed, &cidr.to_string());
		}
		Ok(added)
	})
	.await?;
	let status = if added {
		StatusCode::CREATED
	} else {
		StatusCode::OK
	};
	Ok((
		status,
		Json(AllowChanged {
			changed: added,
			cidr: cidr.to_string(),
		}),
	))
}

pub async fn allow_remove(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(raw): Path<String>,
) -> Result<Json<AllowChanged>, ApiError> {
	let principal = caller(&state, &auth)?;
	let cidr = cidr_of(&raw)?;
	let (store, trail) = (store(&state)?, Trail::new(&principal, ip));
	detached(async move {
		admin::disallow(&*store, cidr, Limits::api()).await?;
		trail.log(BanEvent::Disallowed, &cidr.to_string());
		Ok(())
	})
	.await?;
	Ok(Json(AllowChanged {
		changed: true,
		cidr: cidr.to_string(),
	}))
}
