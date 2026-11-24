//! `GET`, `POST` and `DELETE` on `/api/v1/aliases`: the address aliases that
//! fan one address out to several local accounts.
//!
//! The routes are thin. What an alias may be, who may make one, the caps and
//! the refusals are the rules of [`crate::aliases::edit`], the ones
//! `epistle alias` runs; a route adds what only a request has: the key it
//! came with, the body it carries and the answer it owes.
//!
//! The scope is `alias`, and only `alias`: not `read`, not `write`
//! (`acceptable_scopes_for`). An alias redirects mail, so a key that may only
//! read, or only write accounts, cannot list or change one. A key that is
//! confined to domains makes and removes aliases in those domains only, with
//! every member inside them too, and gets one answer for what does not exist
//! and what is not its own.

use axum::extract::{Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::aliases::view::{self, AliasRow};
use crate::aliases::{AliasError, Origin};
use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::util::address::normalize;

mod change;

pub(super) use change::{create, remove};

/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 100;

/// The page size when the caller names none.
const DEFAULT_LIMIT: usize = 50;

/// The alias origin of `principal`: the domains its key is confined to.
pub(super) fn origin_of(principal: &Principal) -> Origin {
	Origin::Api {
		confined_to: principal.confined_domains().map(<[String]>::to_vec),
	}
}

/// The configuration a route reads and writes against.
pub(super) fn config(state: &ApiState) -> Result<std::sync::Arc<crate::config::Config>, ApiError> {
	state
		.live_domains()
		.map(|live| live.current())
		.ok_or_else(ApiError::internal)
}

/// Map a refusal of the rules to the answer of the route.
pub(super) fn refusal(error: AliasError) -> ApiError {
	match error {
		AliasError::NotFound(message) => ApiError::not_found(&message),
		AliasError::Invalid(message) => ApiError::invalid_input(&message),
		AliasError::Exists(message) => ApiError::conflict(message),
		AliasError::Capped(reached) => ApiError::limit_reached(&reached),
		AliasError::Io(message) => {
			tracing::error!(%message, "alias state commit failed");
			ApiError::internal()
		}
	}
}

/// The query of `GET /api/v1/aliases`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
	/// Only the aliases that deliver to this account.
	account: Option<String>,
	/// Only the aliases in this domain.
	domain: Option<String>,
	limit: Option<usize>,
	/// The `next_cursor` of the page before.
	cursor: Option<String>,
}

/// A page of aliases.
#[derive(Debug, Serialize)]
pub struct Page {
	/// The aliases, ordered by address.
	aliases: Vec<AliasRow>,
	/// Pass as `cursor` to fetch the next page; absent on the last page.
	#[serde(skip_serializing_if = "Option::is_none")]
	next_cursor: Option<String>,
}

/// Whether the key may see `row`: its address and every member are inside the
/// domains the key is confined to. An alias with a member the key could not
/// have named is not shown, so a listing cannot name an address of another
/// tenant.
fn visible(principal: &Principal, row: &AliasRow) -> bool {
	let inside = |address: &str| {
		crate::util::address_reason::parse(address)
			.map(|parsed| principal.admits_domain(parsed.domain()))
			.unwrap_or(false)
	};
	inside(&row.address) && row.members.iter().all(|member| inside(member))
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(query): Query<ListQuery>,
) -> Result<Json<Page>, ApiError> {
	let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
	if limit == 0 {
		return Err(ApiError::field_out_of_range(
			"limit",
			"limit must be at least 1",
		));
	}
	let principal = Principal::for_token(&state, &auth);
	let domain = match &query.domain {
		Some(raw) => {
			let domain = crate::domain::normalize(raw)
				.map_err(|_| ApiError::invalid_input("domain is not a valid domain name"))?;
			if !principal.admits_domain(&domain) {
				return Err(ApiError::not_found("no such domain"));
			}
			Some(domain)
		}
		None => None,
	};
	let account_addresses = match &query.account {
		Some(name) => {
			super::scope::account_in_scope(&state, &principal, name)?;
			let addresses = state
				.store()
				.account_views()
				.into_iter()
				.find(|(known, _, _)| known == name)
				.map(|(_, addresses, _)| addresses)
				.ok_or_else(|| ApiError::not_found("no such account"))?;
			Some(
				addresses
					.iter()
					.map(|address| normalize(address))
					.collect::<Vec<_>>(),
			)
		}
		None => None,
	};
	let config = config(&state)?;
	let mut now = (*config).clone();
	now.alias = crate::aliases::current(&config);
	let mut rows: Vec<AliasRow> = view::rows(&now)
		.into_iter()
		.filter(|row| visible(&principal, row))
		.filter(|row| {
			domain.as_deref().is_none_or(|wanted| {
				row.address
					.rsplit_once('@')
					.is_some_and(|(_, found)| found.eq_ignore_ascii_case(wanted))
			})
		})
		.filter(|row| {
			account_addresses.as_ref().is_none_or(|addresses| {
				row.members
					.iter()
					.any(|member| addresses.contains(&normalize(member)))
			})
		})
		.collect();
	rows.sort_by_key(|row| normalize(&row.address));
	if let Some(cursor) = &query.cursor {
		let cursor = normalize(cursor);
		rows.retain(|row| normalize(&row.address) > cursor);
	}
	let more = rows.len() > limit;
	rows.truncate(limit);
	let next_cursor = more
		.then(|| rows.last().map(|row| normalize(&row.address)))
		.flatten();
	Ok(Json(Page {
		aliases: rows,
		next_cursor,
	}))
}

#[cfg(test)]
mod tests;
