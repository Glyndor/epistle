//! Shared domain write boundary. Only the watcher publishes running state.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;

use crate::api::audit::{Carried, DomainEvent, log_domain_change};
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::api::{Principal, error::ApiError};
use crate::domain::state::{Change, Committed, EditError};

#[derive(Debug, Serialize)]
pub struct Changed {
	pub changed: bool,
	pub domain: String,
	/// The write is durable; the watcher applies it to the running server.
	pub reload: &'static str,
}

impl Changed {
	pub(super) fn of(done: &Committed, domain: String) -> Self {
		Self {
			changed: done.changed,
			domain,
			reload: if done.changed { "watcher" } else { "none" },
		}
	}
}

pub(super) fn refusal(error: EditError) -> ApiError {
	match error {
		EditError::NotFound(message) => ApiError::not_found(&message),
		EditError::Invalid(message) => ApiError::invalid_input(&message),
		EditError::Exists(message) | EditError::InUse(message) | EditError::Policy(message) => {
			ApiError::conflict(message)
		}
		EditError::Io(message) => {
			tracing::error!(%message, "domain state commit failed");
			ApiError::internal()
		}
	}
}

pub(super) fn canonical(field: &str, raw: &str) -> Result<String, ApiError> {
	crate::domain::state::edit::rules::canonical(field, raw).map_err(refusal)
}

pub(super) fn in_scope(principal: &Principal, domain: &str) -> Result<(), ApiError> {
	if principal.admits_domain(domain) {
		Ok(())
	} else {
		Err(ApiError::not_found("no such domain"))
	}
}

/// Read the configured seed without publishing anything. The commit itself
/// reads domains.toml again under its lock, even if the watcher is behind.
pub(super) fn config(state: &ApiState) -> Result<std::sync::Arc<crate::config::Config>, ApiError> {
	state
		.live_domains()
		.map(|live| live.current())
		.ok_or_else(ApiError::internal)
}

/// What the audit line of a domain change says. It is written on the
/// blocking thread that commits, so a client that drops the request after the
/// commit still leaves the line (see [`crate::api::audit::Carried`]).
pub(super) struct Trail {
	pub(super) event: DomainEvent,
	pub(super) domain: String,
	pub(super) ip: ClientIp,
}

impl Trail {
	pub(super) fn new(event: DomainEvent, domain: &str, ip: ClientIp) -> Self {
		Self {
			event,
			domain: domain.to_string(),
			ip,
		}
	}

	/// Write the line of a change that was made.
	pub(super) fn log(&self, carried: &Carried, done: &Committed) {
		if done.changed {
			carried.run(|| log_domain_change(self.event, &self.domain, self.ip.0));
		}
	}
}

pub(super) async fn commit(
	state: &ApiState,
	change: Change,
	alias_target: Option<String>,
	trail: Trail,
) -> Result<Committed, ApiError> {
	commit_with(state, change, alias_target, false, trail).await
}

/// The in-use refusal names other tenants' aliases, accounts and tenants.
/// With `redact_in_use` it says only that the domain is in use, for a key
/// that does not see those entities anywhere else.
pub(super) async fn commit_with(
	state: &ApiState,
	change: Change,
	alias_target: Option<String>,
	redact_in_use: bool,
	trail: Trail,
) -> Result<Committed, ApiError> {
	let config = config(state)?;
	let carried = Carried::capture();
	tokio::task::spawn_blocking(move || {
		let done = crate::domain::state::edit::commit_checked(&config, &change, |_, file| {
			if let Some(target) = &alias_target {
				if file.domain(target).is_none() {
					return Err(EditError::NotFound(format!(
						"domain {target} is not configured"
					)));
				}
				if let Change::AliasRemove { alias } = &change
					&& file
						.alias(alias)
						.is_some_and(|(_, actual)| !actual.eq_ignore_ascii_case(target))
				{
					return Err(EditError::NotFound(format!(
						"domain alias {alias} is not declared"
					)));
				}
			}
			Ok(())
		})?;
		trail.log(&carried, &done);
		Ok(done)
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(|error| match error {
		EditError::InUse(_) if redact_in_use => ApiError::conflict("domain is still in use"),
		other => refusal(other),
	})
}

pub async fn remove(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Extension(ip): Extension<ClientIp>,
	Path(raw): Path<String>,
) -> Result<Json<Changed>, ApiError> {
	let domain = canonical("domain", &raw)?;
	let principal = Principal::for_token(&state, &auth);
	in_scope(&principal, &domain)?;
	let redact = !principal.is_unrestricted();
	let trail = Trail::new(DomainEvent::Removed, &domain, ip);
	let done = commit_with(&state, Change::Remove { name: raw }, None, redact, trail).await?;
	Ok(Json(Changed::of(&done, domain)))
}
