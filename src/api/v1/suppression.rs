//! `GET /api/v1/suppression` and `DELETE /api/v1/suppression/{address}`.
//!
//! Lists or clears suppressed recipient addresses. With `?account=<addr>` the
//! operation targets that sending account's per-account list; without it, the
//! global list.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::queue::SuppressionList;

/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 100;

#[derive(Deserialize)]
pub struct ListParams {
	/// Restrict to a sending account's per-account list.
	account: Option<String>,
	limit: Option<usize>,
	/// Keyset cursor: return addresses strictly after this one.
	after: Option<String>,
}

#[derive(Serialize)]
pub struct SuppressionPage {
	addresses: Vec<String>,
	/// Pass as `after` to fetch the next page; absent on the last page.
	#[serde(skip_serializing_if = "Option::is_none")]
	next_cursor: Option<String>,
}

fn open(state: &ApiState) -> Result<SuppressionList, ApiError> {
	SuppressionList::open(state.data_dir()).map_err(|_| ApiError::internal())
}

/// List suppressed addresses (global, or per-account with `?account=`).
pub async fn list(
	State(state): State<ApiState>,
	Query(params): Query<ListParams>,
) -> Result<Json<SuppressionPage>, ApiError> {
	let limit = params.limit.unwrap_or(50).min(MAX_LIMIT);
	if limit == 0 {
		return Err(ApiError::invalid_input("limit must be at least 1"));
	}
	let suppression = open(&state)?;
	let all = match &params.account {
		Some(account) => suppression.list_for(account),
		None => suppression.list(),
	};
	let start = match &params.after {
		Some(cursor) => all.partition_point(|a| a <= cursor),
		None => 0,
	};
	let page: Vec<String> = all.iter().skip(start).take(limit).cloned().collect();
	let next_cursor = if start + page.len() < all.len() {
		page.last().cloned()
	} else {
		None
	};
	Ok(Json(SuppressionPage {
		addresses: page,
		next_cursor,
	}))
}

#[derive(Deserialize)]
pub struct RemoveParams {
	account: Option<String>,
}

#[derive(Serialize)]
pub struct Removed {
	removed: String,
}

/// Remove an address from the global list, or an account's with `?account=`.
pub async fn remove(
	State(state): State<ApiState>,
	Path(address): Path<String>,
	Query(params): Query<RemoveParams>,
) -> Result<Json<Removed>, ApiError> {
	let suppression = open(&state)?;
	let result = match &params.account {
		Some(account) => suppression.remove_for(account, &address),
		None => suppression.remove(&address),
	};
	result.map_err(|_| ApiError::internal())?;
	Ok(Json(Removed { removed: address }))
}
