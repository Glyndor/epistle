//! `POST /api/v1/aliases` and `DELETE /api/v1/aliases/{alias}`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::aliases::edit::{self, NewAlias};
use crate::aliases::view::AliasRow;
use crate::aliases::{Change, Committed};
use crate::api::Principal;
use crate::api::audit::{AliasEvent, Carried, log_alias_change};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::util::address::normalize;

use super::{config, origin_of, refusal};

/// The longest address any field of a request may carry (RFC 5321).
const MAX_ADDRESS: usize = 320;

/// The body of `POST /api/v1/aliases`: the alias and either the addresses it
/// delivers to or the one account it is for.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
	/// The alias address.
	alias: String,
	/// The addresses it delivers to: accounts of this server.
	#[serde(default)]
	members: Vec<String>,
	/// The account it delivers to, instead of `members`.
	#[serde(default)]
	target_account: Option<String>,
	/// Check the request and change nothing.
	#[serde(default)]
	dry_run: bool,
}

/// The answer to a create.
#[derive(Debug, Serialize)]
pub struct Created {
	alias: AliasRow,
	/// `false` for a dry run, which writes nothing.
	changed: bool,
	dry_run: bool,
	/// The write is durable; the watcher applies it to the running server.
	reload: &'static str,
}

/// The query of `DELETE /api/v1/aliases/{alias}`.
#[derive(Debug, Deserialize)]
pub struct RemoveQuery {
	#[serde(default)]
	dry_run: bool,
}

/// The answer to a remove.
#[derive(Debug, Serialize)]
pub struct Removed {
	alias: String,
	changed: bool,
	dry_run: bool,
	reload: &'static str,
}

fn bounded(field: &str, value: &str) -> Result<(), ApiError> {
	if value.len() > MAX_ADDRESS {
		return Err(ApiError::invalid_input(&format!(
			"{field} is longer than an address can be"
		)));
	}
	Ok(())
}

/// The address `target_account` stands for as a member of the alias at
/// `alias_address`: its address in the alias's domain when it has one, else
/// its first. An account that does not exist and one the key may not use give
/// the same answer.
fn target_member(
	state: &ApiState,
	principal: &Principal,
	name: &str,
	alias_address: &str,
) -> Result<String, ApiError> {
	let unavailable = || ApiError::invalid_input("target_account is not available");
	let (_, addresses, _) = state
		.store()
		.account_views()
		.into_iter()
		.find(|(known, _, _)| known == name)
		.ok_or_else(unavailable)?;
	if !principal.admits_account(name, &addresses) {
		return Err(unavailable());
	}
	let domain = alias_address
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_ascii_lowercase());
	let same_domain = addresses.iter().find(|address| {
		address
			.rsplit_once('@')
			.is_some_and(|(_, found)| Some(found.to_ascii_lowercase()) == domain)
	});
	same_domain
		.or_else(|| addresses.first())
		.cloned()
		.ok_or_else(unavailable)
}

/// What the audit line of a change says, carried to the blocking thread that
/// makes it.
struct Trail {
	event: AliasEvent,
	/// The normalized alias address.
	alias: String,
	/// The label of the key, `None` for the configured token.
	key: Option<String>,
	ip: Option<std::net::IpAddr>,
}

/// Run `change` on a blocking thread: the rules read files and take locks.
/// The audit line of a durable change is written there too, right after the
/// commit: the thread runs to the end even when the client drops the request,
/// and a line left to the handler would be lost with it.
async fn run(
	config: std::sync::Arc<crate::config::Config>,
	change: Change,
	origin: crate::aliases::Origin,
	dry_run: bool,
	trail: Trail,
) -> Result<Committed, ApiError> {
	let carried = Carried::capture();
	tokio::task::spawn_blocking(move || {
		if dry_run {
			return edit::preview(&config, &change, &origin);
		}
		let done = edit::commit(&config, &change, &origin)?;
		if done.changed {
			carried.run(|| {
				log_alias_change(trail.event, &trail.alias, trail.key.as_deref(), trail.ip);
			});
		}
		Ok(done)
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(refusal)
}

pub async fn create(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Json(request): Json<Create>,
) -> Result<(StatusCode, Json<Created>), ApiError> {
	bounded("alias", &request.alias)?;
	for member in &request.members {
		bounded("members", member)?;
	}
	let principal = Principal::for_token(&state, &auth);
	let members = match (&request.target_account, request.members.is_empty()) {
		(Some(name), true) => {
			bounded("target_account", name)?;
			vec![target_member(&state, &principal, name, &request.alias)?]
		}
		(None, false) => request.members.clone(),
		_ => {
			return Err(ApiError::invalid_input(
				"give either members or target_account, and not both",
			));
		}
	};
	let change = Change::Add(NewAlias {
		address: request.alias.clone(),
		members,
		senders: Vec::new(),
		list_id: None,
		hidden: true,
	});
	let done = run(
		config(&state)?,
		change,
		origin_of(&principal),
		request.dry_run,
		Trail {
			event: AliasEvent::Added,
			alias: normalize(&request.alias),
			key: principal.key_label().map(str::to_string),
			ip: ip.0,
		},
	)
	.await?;
	let alias = done
		.after
		.alias(&request.alias)
		.map(|alias| AliasRow::of(alias, &std::collections::HashSet::new()))
		.ok_or_else(ApiError::internal)?;
	let status = if request.dry_run {
		StatusCode::OK
	} else {
		StatusCode::CREATED
	};
	Ok((
		status,
		Json(Created {
			alias,
			changed: done.changed && !request.dry_run,
			dry_run: request.dry_run,
			reload: if done.changed && !request.dry_run {
				"watcher"
			} else {
				"none"
			},
		}),
	))
}

pub async fn remove(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(alias): Path<String>,
	Query(query): Query<RemoveQuery>,
) -> Result<Json<Removed>, ApiError> {
	bounded("alias", &alias)?;
	let principal = Principal::for_token(&state, &auth);
	let change = Change::Remove {
		address: alias.clone(),
	};
	let done = run(
		config(&state)?,
		change,
		origin_of(&principal),
		query.dry_run,
		Trail {
			event: AliasEvent::Removed,
			alias: normalize(&alias),
			key: principal.key_label().map(str::to_string),
			ip: ip.0,
		},
	)
	.await?;
	Ok(Json(Removed {
		alias: normalize(&alias),
		changed: done.changed && !query.dry_run,
		dry_run: query.dry_run,
		reload: if done.changed && !query.dry_run {
			"watcher"
		} else {
			"none"
		},
	}))
}
