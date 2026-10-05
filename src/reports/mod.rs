//! Ingest DMARC aggregate and TLS-RPT reports that arrive for our domains.
//!
//! The DMARC and TLS-RPT TXT records we publish point `rua=` at
//! `postmaster@<domain>` and `tlsrpt@<domain>`. The deliverer copies each
//! report to its named account and then hands the raw bytes to
//! [`ingest`], which finds the part, decompresses it, parses it and
//! appends one JSONL line per report under `data_dir/reports/`.
//!
//! Errors do not block delivery. The mail still lands in the mailbox; the
//! operator can read the raw report there. The hook only logs and counts.

mod bounds;
mod decompress;
pub mod dmarc;
mod mime;
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

	/// Sum of failing rows (DMARC) or failed sessions (TLS-RPT) the
	/// metrics counter will add.
	fn failing_count(&self) -> u64 {
		match self {
			Parsed::Dmarc(r) => r.failing_count(),
			Parsed::TlsRpt(r) => r.failing_count(),
		}
	}
}

/// Ingest one inbound report message. Failures are logged at `warn` with
/// the reason and counted via `reports_dropped`; they do not affect
/// delivery (the mail still reaches the named mailbox). `metrics` is
/// optional: when `None`, the report is still parsed and persisted, only
/// the counters are skipped (the operator's terminal still sees the log
/// line).
pub fn ingest(data_dir: &Path, kind: Kind, message: &AcceptedMessage, metrics: Option<&Metrics>) {
	let report = match ingest_inner(kind, &message.data) {
		Ok(report) => report,
		Err(reason) => {
			if let Some(metrics) = metrics {
				metrics.reports_dropped();
			}
			tracing::warn!(kind = kind.dir_name(), %reason, "report ingestion failed");
			return;
		}
	};
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

fn ingest_inner(kind: Kind, raw: &[u8]) -> Result<Parsed, String> {
	let part = mime::find_report_part(raw, kind).map_err(|e| e.to_string())?;
	let (encoding, bytes) = (part.encoding, part.bytes);
	let inflated = decompress::inflate_attachment(&bytes, encoding).map_err(|e| e.to_string())?;
	match kind {
		Kind::Dmarc => dmarc::parse(&inflated)
			.map(Parsed::Dmarc)
			.map_err(|e| e.to_string()),
		Kind::TlsRpt => tlsrpt::parse(&inflated)
			.map(Parsed::TlsRpt)
			.map_err(|e| e.to_string()),
	}
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
#[path = "ingest_tests.rs"]
mod tests;
