//! `GET /api/v1/dns/records`.

use axum::extract::{Query, State};
use axum::{Extension, Json};
use serde::Serialize;

use super::{Scope, select, too_many};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::dns::listing::{self, Row, Skipped};

/// Most hosted domains one listing covers.
pub(super) const MOST_DOMAINS: usize = 200;

/// The records a configuration needs.
#[derive(Debug, Serialize)]
pub struct Records {
	/// The records to publish, the rows `epistle dns-records --json` prints.
	records: Vec<Row>,
	/// The groups the configuration skips: those records are not published,
	/// so they are not missing.
	skipped: Vec<Skipped>,
	/// False when an input could not be read (a key file, the certificate):
	/// the list may lack a record the configuration needs, and the server's
	/// log says which input.
	complete: bool,
}

pub async fn records(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(query): Query<Scope>,
) -> Result<Json<Records>, ApiError> {
	let selection = select(&state, &auth, &query)?;
	too_many(selection.domains.len(), MOST_DOMAINS)?;
	if selection.domains.is_empty() && !selection.with_host {
		// A key that reaches no hosted domain has nothing to list, and
		// nothing is read for it.
		return Ok(Json(Records {
			records: Vec::new(),
			skipped: Vec::new(),
			complete: true,
		}));
	}
	let found = tokio::task::spawn_blocking(move || {
		listing::of_domains(&selection.config, &selection.domains, selection.with_host)
	})
	.await
	.map_err(|_| ApiError::internal())?
	.map_err(|errors| {
		for error in errors {
			tracing::error!(%error, "the DNS records cannot be computed");
		}
		ApiError::internal()
	})?;
	for warning in &found.warnings {
		tracing::warn!(%warning, "the DNS records are incomplete");
	}
	Ok(Json(Records {
		records: listing::rows(&found.records),
		skipped: found.skipped,
		complete: found.complete,
	}))
}
