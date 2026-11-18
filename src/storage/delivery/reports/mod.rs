//! Report-ingest hook: when an envelope recipient is `postmaster@<domain>`
//! or `tlsrpt@<domain>` for one of the served domains, or for the server's
//! own name, hand the raw message to the report ingester, which decides from
//! the message what kind of report it is, if it is one. Failures never block
//! delivery; the mailbox copy still lands so the operator can read the raw
//! report.

use std::path::Path;

use crate::reports;
use crate::smtp::address::Address;
use crate::smtp::session::AcceptedMessage;

/// Inspect `message.recipients`; when an envelope recipient has the local
/// part `postmaster` or `tlsrpt` and its domain is in the directory's report
/// domains, call `crate::reports::ingest(...)` once for the message, however many
/// of its recipients are report mailboxes.
pub(super) fn ingest_for_recipients(
	data_dir: &Path,
	directory_handle: &crate::directory_store::DirectoryHandle,
	metrics: Option<&std::sync::Arc<crate::metrics::Metrics>>,
	message: &AcceptedMessage,
) {
	let domains = directory_handle.current().report_domains();
	if domains.is_empty() {
		return;
	}
	let expected = message.recipients.iter().any(|recipient| {
		Address::parse(recipient).is_ok_and(|address| {
			is_report_target(
				&address.local_part().to_ascii_lowercase(),
				address.domain(),
				&domains,
			)
		})
	});
	if expected {
		reports::ingest(data_dir, message, metrics.map(|arc| arc.as_ref()));
	}
}

/// Hand the message to the feedback-loop receiver when an envelope
/// recipient is the mailbox the operator named for it.
pub(super) fn process_fbl(
	fbl: &reports::fbl::Fbl,
	data_dir: &Path,
	directory_handle: &crate::directory_store::DirectoryHandle,
	metrics: &Option<std::sync::Arc<crate::metrics::Metrics>>,
	message: &AcceptedMessage,
) {
	if message
		.recipients
		.iter()
		.any(|recipient| fbl.is_mailbox(recipient))
	{
		reports::fbl::process(
			fbl,
			data_dir,
			&directory_handle.current(),
			message,
			metrics.as_deref(),
		);
	}
}

/// Whether `local@domain` is a report mailbox: the local part is `postmaster`
/// or `tlsrpt` and the domain is one the server answers for.
fn is_report_target(local: &str, domain: &str, domains: &[String]) -> bool {
	domains.iter().any(|d| d == domain) && matches!(local, "postmaster" | "tlsrpt")
}

#[cfg(test)]
mod tests;
