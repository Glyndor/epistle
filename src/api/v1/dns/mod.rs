//! `GET /api/v1/dns/records` and `GET /api/v1/dns/verify`: what `epistle
//! dns-records --json` and `epistle verify-dns --json` print, through the
//! code the commands run ([`crate::dns::listing`], [`crate::dns::verify`]).
//!
//! Both are reads, so the scope is `read`. What they say is public once the
//! records are in DNS, but the set also carries the mail host, which is the
//! operator's and not a tenant's, so a key confined to some domains gets the
//! records of those domains and not the host's: no address records of the
//! hostname, no TLSA record of it, no check of the hostname. A key naming
//! another tenant's domain, or one the server does not host, is told the
//! same `404`.

use std::sync::Arc;

use serde::Deserialize;

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::config::Config;

#[cfg(test)]
pub(crate) mod parity;
mod records;
mod verify;

pub(super) use records::records;
pub(super) use verify::verify;

/// The query both routes take.
#[derive(Debug, Deserialize)]
pub struct Scope {
	/// Only this hosted domain. Without it, every hosted domain the key
	/// reaches, and the mail host when the key has no domain or account
	/// restriction.
	domain: Option<String>,
}

/// Which names a request is about.
pub(super) struct Selection {
	pub(super) config: Arc<Config>,
	/// The hosted domains, in the configuration's spelling.
	pub(super) domains: Vec<String>,
	/// Whether the mail host is part of the answer: only for a key with no
	/// domain or account restriction, and only when no single domain was named.
	pub(super) with_host: bool,
}

/// The answer for a domain that is not hosted and for one outside the key's
/// domains, so the status cannot list the other tenants' domains.
fn not_hosted() -> ApiError {
	ApiError::not_found("no such domain")
}

/// The hosted domains the request is about.
pub(super) fn select(
	state: &ApiState,
	auth: &MatchedAuth,
	query: &Scope,
) -> Result<Selection, ApiError> {
	let config = state
		.live_domains()
		.map(|live| live.current())
		.ok_or_else(ApiError::internal)?;
	let principal = Principal::for_token(state, auth);
	let domains = match &query.domain {
		Some(named) => {
			let found = config
				.domains
				.iter()
				.find(|hosted| hosted.eq_ignore_ascii_case(named))
				.filter(|hosted| principal.admits_domain(hosted))
				.ok_or_else(not_hosted)?;
			vec![found.clone()]
		}
		None => config
			.domains
			.iter()
			.filter(|hosted| principal.admits_domain(hosted))
			.cloned()
			.collect(),
	};
	let with_host = principal.is_unrestricted() && query.domain.is_none();
	Ok(Selection {
		config,
		domains,
		with_host,
	})
}

/// Most domains one request may cover: the answer and the work grow with
/// them, and a request for more names one domain with `?domain=`.
pub(super) fn too_many(count: usize, most: usize) -> Result<(), ApiError> {
	if count > most {
		return Err(ApiError::field_out_of_range(
			"domain",
			&format!(
				"this covers {count} domains and a request takes at most {most}: name one with ?domain="
			),
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests;
