//! Report-ingest hook: when an envelope recipient is `postmaster@<domain>`
//! or `tlsrpt@<domain>` for one of the served domains, hand the raw
//! message to the DMARC / TLS-RPT ingester. Failures never block delivery;
//! the mailbox copy still lands so the operator can read the raw report.

use std::collections::BTreeSet;
use std::path::Path;

use crate::reports::{self, Kind};
use crate::smtp::address::Address;
use crate::smtp::session::AcceptedMessage;

/// A `(Kind, domain)` pair whose ingest has already fired for the current
/// message. Used to deduplicate when the same report arrives for several
/// accounts via an alias fan-out.
pub(super) type Ingested = BTreeSet<(Kind, String)>;

/// Inspect `message.recipients`; for every envelope recipient whose local
/// part is `postmaster` or `tlsrpt` and whose domain is in `domains`, call
/// `crate::reports::ingest(...)`. Fires once per `(Kind, domain)` pair.
pub(super) fn ingest_for_recipients(
	data_dir: &Path,
	directory_handle: &crate::directory_store::DirectoryHandle,
	metrics: Option<&std::sync::Arc<crate::metrics::Metrics>>,
	message: &AcceptedMessage,
	ingested: &mut Ingested,
) {
	let domains = directory_handle.current().domains();
	if domains.is_empty() {
		return;
	}
	for recipient in &message.recipients {
		let Ok(address) = Address::parse(recipient) else {
			continue;
		};
		let domain = address.domain();
		let local = address.local_part().to_ascii_lowercase();
		let Some(kind) = report_kind(&local, domain, &domains) else {
			continue;
		};
		if !ingested.insert((kind, domain.to_string())) {
			continue;
		}
		reports::ingest(data_dir, kind, message, metrics.map(|arc| arc.as_ref()));
	}
}

/// Map a `local@domain` recipient to a [`Kind`] if the local part is a
/// recognised report target and the domain is one the server serves.
fn report_kind(local: &str, domain: &str, domains: &[String]) -> Option<Kind> {
	if !domains.iter().any(|d| d == domain) {
		return None;
	}
	match local {
		"postmaster" => Some(Kind::Dmarc),
		"tlsrpt" => Some(Kind::TlsRpt),
		_ => None,
	}
}

#[cfg(test)]
#[path = "delivery_reports_tests.rs"]
mod tests;
