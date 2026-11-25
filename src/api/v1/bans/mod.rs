//! `/api/v1/bans`: the bans in force, banning an address or a network,
//! lifting a ban, and the allow list. What `epistle ban` does, through the
//! code it runs ([`crate::antispam::bans::operator`]).
//!
//! The scope is `ban`, and only `ban`: not `read`, not `write`
//! (`acceptable_scopes_for`). A ban locks clients out and the allow list
//! exempts them from every ban, so a key that can only read or only write
//! accounts reaches neither. The bans belong to the server and not to a
//! tenant, so a key confined to domains is refused (`403`), and so is one
//! bound to an account (by the check every administrative route has).
//!
//! A key is held to a narrower reach than the operator at a terminal
//! ([`Limits::api`]): no network wider than a /16 of IPv4 or a /32 of IPv6
//! may be banned or allowed.

use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::antispam::bans::operator::{self as admin, BanAdmin, Limits, Refusal};
use crate::antispam::bans::{BanTarget, UnbanTarget, parse_allow};
use crate::api::Principal;
use crate::api::audit::{BanEvent, Carried, log_ban_change};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};

mod allow;

pub(super) use allow::{allow_add, allow_list, allow_remove};

/// Largest body a write takes.
pub(super) const MAX_BODY: usize = 4096;
/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 500;
/// The page size when the caller names none.
const DEFAULT_LIMIT: usize = 100;

/// The principal, once it is known to be one the ban routes are for.
pub(super) fn caller(state: &ApiState, auth: &MatchedAuth) -> Result<Principal, ApiError> {
	let principal = Principal::for_token(state, auth);
	super::scope::require_unconfined(&principal, "the ban list")?;
	Ok(principal)
}

/// The store, or the answer for a server that has none.
pub(super) fn store(state: &ApiState) -> Result<std::sync::Arc<dyn BanAdmin>, ApiError> {
	state
		.ban_admin()
		.cloned()
		.ok_or_else(|| ApiError::not_found("bans are not manageable: no [database] is configured"))
}

/// What a change needs to write its audit line from another task.
pub(super) struct Trail {
	carried: Carried,
	key: Option<String>,
	ip: Option<std::net::IpAddr>,
}

impl Trail {
	pub(super) fn new(principal: &Principal, ip: ClientIp) -> Self {
		Trail {
			carried: Carried::capture(),
			key: principal.key_label().map(str::to_owned),
			ip: ip.0,
		}
	}

	/// Write the line of a change that was made.
	pub(super) fn log(&self, event: BanEvent, subject: &str) {
		self.carried
			.run(|| log_ban_change(event, subject, self.key.as_deref(), self.ip));
	}
}

/// Run a change, and the line that records it, on a task of its own. A client
/// that goes away drops the handler, and a change already made must not be
/// left without its line: the task is not cancelled with the request.
pub(super) async fn detached<T: Send + 'static>(
	change: impl Future<Output = Result<T, Refusal>> + Send + 'static,
) -> Result<T, ApiError> {
	tokio::spawn(change)
		.await
		.map_err(|_| ApiError::internal())?
		.map_err(refusal)
}

/// The current epoch second.
pub(super) fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
}

/// The answer to a refused operation.
pub(super) fn refusal(refusal: Refusal) -> ApiError {
	match refusal {
		Refusal::AllowListed(_) | Refusal::Full(_) => ApiError::conflict(refusal.to_string()),
		Refusal::TooWide(message) => ApiError::invalid_input(&message),
		Refusal::NoBan(_) | Refusal::NotAllowed(_) => ApiError::not_found(&refusal.to_string()),
		Refusal::Store(error) => {
			tracing::error!(%error, "ban store failed");
			ApiError::internal()
		}
	}
}

/// One ban as `epistle ban list --json` prints it.
#[derive(Debug, Serialize)]
pub struct BanJson {
	subject: String,
	reason: String,
	until: u64,
}

/// A page of bans.
#[derive(Debug, Serialize)]
pub struct Page {
	/// The bans in force, ordered by subject.
	bans: Vec<BanJson>,
	/// Pass as `cursor` to fetch the next page; absent on the last page.
	#[serde(skip_serializing_if = "Option::is_none")]
	next_cursor: Option<String>,
}

/// The query of `GET /api/v1/bans`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
	limit: Option<usize>,
	/// The `next_cursor` of the page before.
	cursor: Option<String>,
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
	caller(&state, &auth)?;
	let mut rows = store(&state)?
		.list_bans(now())
		.await
		.map_err(|error| refusal(error.into()))?;
	// Byte order of the subject, whatever the collation of the database.
	rows.sort_by(|a, b| a.subject.cmp(&b.subject));
	if let Some(cursor) = &query.cursor {
		rows.retain(|row| row.subject.as_str() > cursor.as_str());
	}
	let more = rows.len() > limit;
	rows.truncate(limit);
	let next_cursor = more
		.then(|| rows.last().map(|row| row.subject.clone()))
		.flatten();
	Ok(Json(Page {
		bans: rows
			.into_iter()
			.map(|row| BanJson {
				subject: row.subject,
				reason: row.reason,
				until: row.until_secs,
			})
			.collect(),
		next_cursor,
	}))
}

/// The body of `POST /api/v1/bans`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ban {
	/// An address (`203.0.113.9`) or a network (`203.0.113.0/24`).
	target: String,
	/// How long the ban lasts: a number and a unit `s`, `m`, `h`, `d` or
	/// `w`. A day when absent.
	#[serde(rename = "for")]
	duration: Option<String>,
}

/// The answer to a ban.
#[derive(Debug, Serialize)]
pub struct Banned {
	changed: bool,
	target: String,
	/// Unix seconds the ban ends.
	until: u64,
}

pub async fn ban(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Json(request): Json<Ban>,
) -> Result<(StatusCode, Json<Banned>), ApiError> {
	let principal = caller(&state, &auth)?;
	let target = BanTarget::parse(&request.target)
		.map_err(|message| ApiError::value_not_allowed("target", &message))?;
	let duration = match &request.duration {
		Some(text) => Some(
			admin::parse_duration(text)
				.map_err(|message| ApiError::value_not_allowed("for", &message))?,
		),
		None => None,
	};
	let (store, trail) = (store(&state)?, Trail::new(&principal, ip));
	let banned = detached(async move {
		let banned = admin::ban(&*store, target, duration, now(), Limits::api()).await?;
		trail.log(BanEvent::Banned, &target.subject());
		Ok(banned)
	})
	.await?;
	Ok((
		StatusCode::CREATED,
		Json(Banned {
			changed: true,
			target: banned.target,
			until: banned.until,
		}),
	))
}

/// The answer to lifting a ban.
#[derive(Debug, Serialize)]
pub struct Unbanned {
	changed: bool,
	target: String,
	/// Bans removed.
	bans: u64,
	/// Failure records cleared.
	failures: u64,
}

pub async fn unban(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(subject): Path<String>,
) -> Result<Json<Unbanned>, ApiError> {
	let principal = caller(&state, &auth)?;
	let target = UnbanTarget::parse(&subject)
		.map_err(|message| ApiError::value_not_allowed("subject", &message))?;
	let (store, trail) = (store(&state)?, Trail::new(&principal, ip));
	let lifted = detached(async move {
		let lifted = admin::unban(&*store, target, Limits::api()).await?;
		trail.log(BanEvent::Unbanned, &lifted.target);
		Ok(lifted)
	})
	.await?;
	Ok(Json(Unbanned {
		changed: true,
		target: lifted.target,
		bans: lifted.bans,
		failures: lifted.failures,
	}))
}

pub(super) fn cidr_of(text: &str) -> Result<crate::cidr::Cidr, ApiError> {
	parse_allow(text).map_err(|message| ApiError::value_not_allowed("cidr", &message))
}

#[cfg(test)]
mod tests;
