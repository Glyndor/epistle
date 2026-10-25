//! `GET /api/v1/deliveries`: stream the per-recipient delivery log.
//!
//! Authorisation is two-tier: an admin (or the configured static token)
//! sees every record, a restricted key sees only the records tagged with an
//! account it may reach. The reach is the one the common authorization
//! decides, so a key confined to a domain sees the records of the accounts
//! inside that domain and nothing else. Records with no account tag are
//! visible only to admins, the same way `/api/v1/queue` treats unattributed
//! entries.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Extension, Query, State};
use serde::{Deserialize, Serialize};

use super::super::Principal;
use super::super::state::{ApiState, MatchedAuth};
use crate::api::error::ApiError;
use crate::storage::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord};

/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 100;

/// Default `limit` when the caller does not pass one.
const DEFAULT_LIMIT: usize = 50;

#[derive(Deserialize)]
pub struct ListParams {
	recipient: Option<String>,
	account: Option<String>,
	since: Option<String>,
	outcome: Option<String>,
	limit: Option<usize>,
}

/// The page of records returned by `GET /api/v1/deliveries`. Always
/// finite: `entries.len() <= limit`.
#[derive(Serialize)]
pub struct DeliveryPage {
	entries: Vec<DeliveryEntry>,
}

/// The wire shape of one record. Mirrors the on-disk log shape so a
/// client of either stays the same.
#[derive(Serialize)]
pub struct DeliveryEntry {
	time: u64,
	spool_id: uuid::Uuid,
	account: Option<String>,
	from: String,
	recipient: String,
	outcome: String,
	remote: Option<String>,
	reply: Option<String>,
	attempt: u32,
	extra: BTreeMap<String, String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(params): Query<ListParams>,
) -> Result<Json<DeliveryPage>, ApiError> {
	let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
	let principal = crate::api::Principal::for_token(&state, &auth);

	// The acting account a restricted key may see is decided by the common
	// authorization: the records it may read are the ones tagged with an
	// account it may reach. A domain-confined key therefore sees the
	// records of the accounts inside its domains, and a record tagged with
	// no account at all belongs to nobody and stays with the admins.
	let scope = Scope::for_principal(&state, &principal);

	// Reject the call up front when the log is off: no record can be
	// read back, the response would be empty, and the operator should
	// know to enable `[storage] delivery_log_days`.
	let retention = state
		.delivery_log_days()
		.unwrap_or(DEFAULT_DELIVERY_LOG_DAYS);
	if retention == 0 {
		return Err(ApiError::not_found("the delivery log is disabled"));
	}

	let outcome_filter = match params
		.outcome
		.as_deref()
		.map(str::trim)
		.filter(|value| !value.is_empty())
	{
		Some(value) => Some(
			DeliveryOutcome::parse(value)
				.ok_or_else(|| ApiError::invalid_input(&format!("unknown outcome {value:?}")))?,
		),
		None => None,
	};
	let now = now_epoch();
	let since_epoch = match params
		.since
		.as_deref()
		.map(str::trim)
		.filter(|value| !value.is_empty())
	{
		Some(value) => match crate::storage::delivery_log::parse_since(value, now) {
			Ok(Some(epoch)) => Some(epoch),
			Ok(None) => None,
			Err(error) => {
				return Err(ApiError::invalid_input(&format!(
					"since {value:?}: {error}"
				)));
			}
		},
		None => None,
	};
	let recipient_filter = params
		.recipient
		.as_deref()
		.map(str::trim)
		.filter(|value| !value.is_empty())
		.map(str::to_string);
	let account_filter = params
		.account
		.as_deref()
		.map(str::trim)
		.filter(|value| !value.is_empty())
		.map(str::to_string);

	// The caller's own account filter narrows the page, but it cannot widen
	// it: a restricted caller naming an account outside its reach gets the
	// reach's own view, never the other tenant's records.
	let account_filter = match &scope {
		Scope::Admin => account_filter,
		Scope::Tenant { reachable, .. } => {
			account_filter.filter(|account| reachable.contains(account))
		}
	};

	let log = DeliveryLog::open(state.data_dir(), retention);
	let outcome_ref = outcome_filter;
	let since_ref = since_epoch;
	let account_ref = account_filter.as_deref();
	let recipient_ref = recipient_filter.as_deref();
	let records = log
		.list(Some(limit), |record| {
			match_filters(
				record,
				&scope,
				account_ref,
				recipient_ref,
				since_ref,
				outcome_ref,
			)
		})
		.map_err(|_| ApiError::internal())?;
	let entries = records
		.into_iter()
		.map(DeliveryEntry::from_record)
		.collect();
	Ok(Json(DeliveryPage { entries }))
}

fn match_filters(
	record: &DeliveryRecord,
	scope: &Scope,
	account: Option<&str>,
	recipient: Option<&str>,
	since: Option<u64>,
	outcome: Option<DeliveryOutcome>,
) -> bool {
	// The account tag decides who may read the record. A restricted caller
	// only sees the records of the accounts it may reach, and a record with
	// no tag belongs to no account: it stays with the administrators.
	if let Scope::Tenant { reachable, caller } = scope {
		let Some(tag) = record.account.as_deref() else {
			return false;
		};
		if !reachable.contains(tag) {
			return false;
		}
		// The sender of the record must also sit inside the caller's
		// domains, the rule the queue applies.
		if !caller.admits_sender(&record.from) {
			return false;
		}
	}
	if let Some(account) = account
		&& record.account.as_deref() != Some(account)
	{
		return false;
	}
	if let Some(recipient) = recipient
		&& record.recipient != recipient
	{
		return false;
	}
	if let Some(since) = since
		&& record.time < since
	{
		return false;
	}
	if let Some(outcome) = outcome
		&& record.outcome != outcome
	{
		return false;
	}
	true
}

impl DeliveryEntry {
	/// Build a wire entry from the on-disk record. The conversion is
	/// mechanical: the wire shape is the storage shape, with the enum
	/// rendered as its `as_str()` form.
	fn from_record(record: DeliveryRecord) -> Self {
		Self {
			time: record.time,
			spool_id: record.spool_id,
			account: record.account,
			from: record.from,
			recipient: record.recipient,
			outcome: record.outcome.as_str().to_string(),
			remote: record.remote,
			reply: record.reply,
			attempt: record.attempt,
			extra: record.extra,
		}
	}
}

/// What a caller is allowed to see.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
	/// An admin or the configured static token: every record, regardless
	/// of the account that produced it.
	Admin,
	/// A restricted caller: only the records tagged with an account it may
	/// reach. The account names are resolved against the directory once,
	/// before the log is read, so the filter never has to walk it again.
	Tenant {
		reachable: std::collections::HashSet<String>,
		caller: Principal,
	},
}

impl Scope {
	fn for_principal(state: &ApiState, principal: &Principal) -> Self {
		if principal.is_unrestricted() {
			return Self::Admin;
		}
		Self::Tenant {
			reachable: state
				.accounts()
				.into_iter()
				.filter(|account| principal.admits_account(&account.name, &account.addresses))
				.map(|account| account.name)
				.collect(),
			caller: principal.clone(),
		}
	}
}

fn now_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

#[cfg(test)]
#[path = "deliveries_tests.rs"]
mod tests;
