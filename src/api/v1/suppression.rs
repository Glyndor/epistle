//! `GET`, `POST /api/v1/suppression` and `DELETE /api/v1/suppression/{address}`.
//!
//! Lists, adds or clears suppressed recipient addresses. With `?account=`, the
//! operation targets an account name or sending address's per-account list;
//! without it, the global list.

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};

use super::scope::require_unconfined;
use crate::queue::SuppressionList;
use crate::suppression::AddError;

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

struct AccountScope {
	keys: Vec<String>,
}

fn account_scope(
	state: &ApiState,
	principal: &Principal,
	requested: &str,
) -> Result<AccountScope, ApiError> {
	let requested = crate::directory_store::account_name(requested);
	let requested_address = crate::util::address::normalize(&requested);
	let views = state.store().account_views();
	let by_name = views
		.iter()
		.find(|(name, _, _)| name == &requested)
		.map(|(name, addresses, _)| (name.clone(), addresses.clone()));
	let by_address = views
		.iter()
		.find(|(_, addresses, _)| {
			addresses
				.iter()
				.any(|address| crate::util::address::normalize(address) == requested_address)
		})
		.map(|(name, addresses, _)| (name.clone(), addresses.clone()));
	let (name, addresses, by_name) = match (by_name, by_address) {
		(Some(account), _) => (account.0, account.1, true),
		(None, Some(account)) => (account.0, account.1, false),
		(None, None) => return Err(ApiError::not_found("no such account")),
	};
	if !principal.admits_account(&name, &addresses) {
		return Err(ApiError::not_found("no such account"));
	}
	let mut keys = if by_name {
		let mut keys = vec![name];
		keys.extend(addresses);
		keys
	} else {
		vec![requested_address]
	};
	keys.sort();
	keys.dedup();
	Ok(AccountScope { keys })
}

fn account_addresses(suppression: &SuppressionList, scope: &AccountScope) -> Vec<String> {
	let mut addresses = scope
		.keys
		.iter()
		.flat_map(|account| suppression.list_for(account))
		.collect::<Vec<_>>();
	addresses.sort();
	addresses.dedup();
	addresses
}

/// List suppressed addresses (global, or per-account with `?account=`).
pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(params): Query<ListParams>,
) -> Result<Json<SuppressionPage>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let scope = match &params.account {
		Some(account) => Some(account_scope(&state, &principal, account)?),
		None => {
			require_unconfined(&principal, "The global suppression list")?;
			None
		}
	};
	let limit = params.limit.unwrap_or(50).min(MAX_LIMIT);
	if limit == 0 {
		return Err(ApiError::invalid_input("limit must be at least 1"));
	}
	let suppression = open(&state)?;
	let all = match &scope {
		Some(scope) => account_addresses(&suppression, scope),
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
pub struct AddRequest {
	address: String,
	reason: Option<String>,
}

#[derive(Serialize)]
pub struct Suppressed {
	suppressed: String,
}

#[derive(Deserialize)]
pub struct AccountParams {
	account: Option<String>,
}

/// Add an address to the global list, or an account's with `?account=`.
pub async fn add(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(params): Query<AccountParams>,
	Json(request): Json<AddRequest>,
) -> Result<Json<Suppressed>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let scope = match &params.account {
		Some(account) => Some(account_scope(&state, &principal, account)?),
		None => {
			require_unconfined(&principal, "The global suppression list")?;
			None
		}
	};
	let suppression = open(&state)?;
	let account_keys: &[String] = scope
		.as_ref()
		.map_or(&[][..], |scope| scope.keys.as_slice());
	let added = crate::suppression::add(
		&suppression,
		&request.address,
		account_keys,
		request.reason.as_deref(),
		crate::suppression::API_DEFAULT_REASON,
	)
	.map_err(|error| match error {
		AddError::InvalidAddress(why) => {
			ApiError::invalid_input(&format!("invalid address: {why}"))
		}
		AddError::InvalidReason(problem) => ApiError::invalid_input(&problem),
		AddError::Storage(_) => ApiError::internal(),
	})?;
	Ok(Json(Suppressed {
		suppressed: added.address,
	}))
}

#[derive(Serialize)]
pub struct Removed {
	removed: String,
}

/// Remove an address from the global list, or an account's with `?account=`.
pub async fn remove(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(address): Path<String>,
	Query(params): Query<AccountParams>,
) -> Result<Json<Removed>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	let scope = match &params.account {
		Some(account) => Some(account_scope(&state, &principal, account)?),
		None => {
			require_unconfined(&principal, "The global suppression list")?;
			None
		}
	};
	let suppression = open(&state)?;
	match scope {
		Some(scope) => {
			for account in scope.keys {
				suppression
					.remove_for(&account, &address)
					.map_err(|_| ApiError::internal())?;
			}
		}
		None => suppression
			.remove(&address)
			.map_err(|_| ApiError::internal())?,
	}
	Ok(Json(Removed { removed: address }))
}
