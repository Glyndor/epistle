//! Ingest DMARC aggregate and TLS-RPT reports that arrive for our domains.
//!
//! The DMARC and TLS-RPT TXT records we publish point `rua=` at
//! `postmaster@<domain>` and `tlsrpt@<domain>`. The deliverer copies each
//! message to its named account and then hands the raw bytes to
//! [`ingest`], which finds the report part, decides from the part which
//! kind it is, decompresses it, parses it and appends one JSONL line per
//! report under `data_dir/reports/`. Both mailboxes receive both kinds,
//! because senders do not always use the address the record names.
//!
//! Errors do not block delivery. The mail still lands in the mailbox; the
//! operator can read the raw report there. The hook only logs and counts.

pub(crate) mod bounds;
mod decompress;

/// The attachment unpacking, for the fuzz target in `crate::fuzzing`.
pub(crate) use decompress::{Encoding, inflate_attachment};
pub mod dmarc;
pub mod fbl;
pub(crate) mod mime;
pub(crate) mod store;
pub mod tlsrpt;

use std::path::Path;

use crate::smtp::session::AcceptedMessage;

/// What kind of report we are looking at in an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
	/// RFC 7489 aggregate (DMARC RUA). Sent by receivers about us.
	Dmarc,
	/// RFC 8460 (TLS-RPT). Sent by receivers about our outbound TLS.
	TlsRpt,
}

impl Kind {
	/// What an `epistle reports` reader calls the bucket.
	fn dir_name(self) -> &'static str {
		match self {
			Kind::Dmarc => "dmarc",
			Kind::TlsRpt => "tlsrpt",
		}
	}
}

/// A parsed report: either a DMARC aggregate or a TLS-RPT report. The
/// enum is the seam between the kind-specific parsers and the persist
/// path: callers `match` on it once instead of going through a trait with
/// `unreachable!` defaults for the wrong kind.
pub enum Parsed {
	/// A parsed DMARC aggregate report.
	Dmarc(dmarc::DmarcReport),
	/// A parsed TLS-RPT report.
	TlsRpt(tlsrpt::TlsReport),
}

impl Parsed {
	/// File-name component the JSONL file is stored under.
	fn org(&self) -> String {
		match self {
			Parsed::Dmarc(r) => r.org(),
			Parsed::TlsRpt(r) => r.org(),
		}
	}

	/// The kind of report this is.
	fn kind(&self) -> Kind {
		match self {
			Parsed::Dmarc(_) => Kind::Dmarc,
			Parsed::TlsRpt(_) => Kind::TlsRpt,
		}
	}

	/// Sum of failing rows (DMARC) or failed sessions (TLS-RPT) the
	/// metrics counter will add.
	fn failing_count(&self) -> u64 {
		match self {
			Parsed::Dmarc(r) => r.failing_count(),
			Parsed::TlsRpt(r) => r.failing_count(),
		}
	}
}

/// Ingest one inbound message addressed to a report mailbox. What the
/// message carries decides how it is read, not the mailbox it came to: a
/// TLS-RPT part goes to the TLS-RPT reader and a DMARC one to the DMARC
/// reader. A message with no report part is logged once at `info` as not a
/// report, with its content types, and is not a failure. Failures are
/// logged at `warn` with the reason and counted via `reports_dropped`; they
/// do not affect delivery (the mail still reaches the named mailbox).
/// `metrics` is optional: when `None`, the report is still parsed and
/// persisted, only the counters are skipped (the operator's terminal still
/// sees the log line).
pub fn ingest(data_dir: &Path, message: &AcceptedMessage, metrics: Option<&Metrics>) {
	let report = match read_report(&message.data, message.tlsrpt_verified) {
		Ok(Some(report)) => report,
		Ok(None) => {
			let content_types = mime::content_types(&message.data).join(", ");
			tracing::info!(%content_types, "message is not a report");
			return;
		}
		Err(failure) => {
			if let Some(metrics) = metrics {
				metrics.reports_dropped();
			}
			tracing::warn!(kind = failure.kind, reason = %failure.reason, "report ingestion failed");
			return;
		}
	};
	let kind = report.kind();
	if let Some(metrics) = metrics {
		metrics.report_ingested(kind);
		let failing = report.failing_count();
		if failing > 0 {
			metrics.report_rows_failing(kind, failing);
		}
	}
	if let Err(error) = persist(data_dir, &report) {
		if let Some(metrics) = metrics {
			metrics.reports_dropped();
		}
		tracing::warn!(kind = kind.dir_name(), %error, "report persist failed");
		return;
	}
	let failing = report.failing_count();
	tracing::info!(
		kind = kind.dir_name(),
		org = %report.org(),
		failing,
		"report ingested"
	);
}

/// Why a message that carries a report could not be read as one.
#[derive(Debug)]
struct ReadFailure {
	/// The kind the message declared, or `"unknown"` when it declared none.
	kind: &'static str,
	reason: String,
}

fn persist(data_dir: &Path, report: &Parsed) -> std::io::Result<()> {
	let today = today_string();
	match report {
		Parsed::Dmarc(r) => dmarc::append(data_dir, &today, r),
		Parsed::TlsRpt(r) => tlsrpt::append(data_dir, &today, r),
	}
}

fn today_string() -> String {
	let ts = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	crate::dmarc::aggregate::unix_to_day(ts)
}

/// Read the report `raw` carries: `Ok(None)` when it carries none.
/// `tlsrpt_verified` says the reporting domain signed the message, which a
/// TLS-RPT report needs before it is believed.
fn read_report(raw: &[u8], tlsrpt_verified: bool) -> Result<Option<Parsed>, ReadFailure> {
	let part = match mime::find_report_part(raw) {
		Ok(part) => part,
		Err(mime::WalkError::NoReportPart) => return Ok(None),
		Err(error) => {
			return Err(ReadFailure {
				kind: "unknown",
				reason: error.to_string(),
			});
		}
	};
	let mut kind = part.kind;
	let failure = |kind: Kind, reason: String| ReadFailure {
		kind: kind.dir_name(),
		reason,
	};
	let inflated = decompress::inflate_attachment(&part.bytes, part.encoding)
		.map_err(|error| failure(kind, error.to_string()))?;
	// A generic `application/gzip` or zip is read as DMARC by its type, but a
	// sender may pack a TLS-RPT JSON document in one: the content settles it.
	if kind == Kind::Dmarc
		&& inflated.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{')
	{
		kind = Kind::TlsRpt;
	}
	if kind == Kind::TlsRpt && !tlsrpt_verified {
		return Err(failure(
			kind,
			"TLS-RPT requires a verified reporting-domain DKIM signature without l=".into(),
		));
	}
	let parsed = match kind {
		Kind::Dmarc => dmarc::parse(&inflated)
			.map(Parsed::Dmarc)
			.map_err(|error| failure(kind, error.to_string())),
		Kind::TlsRpt => tlsrpt::parse(&inflated)
			.map(Parsed::TlsRpt)
			.map_err(|error| failure(kind, error.to_string())),
	};
	parsed.map(Some)
}

/// Days of history `prune` keeps. The same shape as `[storage]
/// deleted_retention_days`: a single integer, no per-bucket knob, so
/// every operator gets the same baseline.
pub const RETENTION_DAYS: u32 = 90;

/// Sweep JSONL report directories older than [`RETENTION_DAYS`]. Called
/// once an hour from the storage-maintenance task.
pub fn prune(data_dir: &Path) {
	let today = today_string();
	store::prune(data_dir, &today, RETENTION_DAYS);
}

/// Convenience re-export so the hook site can spell the metrics type
/// without reaching into the `metrics` module separately.
pub use crate::metrics::Metrics;

#[cfg(test)]
mod tests;
