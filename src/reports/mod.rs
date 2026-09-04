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

mod decompress;
mod dmarc;
mod mime;
mod store;
mod tlsrpt;

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

/// Ingest one inbound report message. Failures are logged at `warn` with
/// the reason and counted via `reports_dropped`; they do not affect
/// delivery (the mail still reaches the named mailbox).
pub fn ingest(data_dir: &Path, kind: Kind, message: &AcceptedMessage, metrics: &Metrics) {
	let report = match ingest_inner(data_dir, kind, &message.data) {
		Ok(report) => report,
		Err(reason) => {
			metrics.reports_dropped();
			tracing::warn!(kind = kind.dir_name(), %reason, "report ingestion failed");
			return;
		}
	};
	metrics.report_ingested(kind);
	let failing = report.failing_count();
	if failing > 0 {
		metrics.report_rows_failing(kind, failing);
	}
	if let Err(error) = persist(data_dir, kind, report.as_ref()) {
		metrics.reports_dropped();
		tracing::warn!(kind = kind.dir_name(), %error, "report persist failed");
		return;
	}
	tracing::info!(
		kind = kind.dir_name(),
		org = %report.org(),
		failing,
		"report ingested"
	);
}

fn persist(data_dir: &Path, kind: Kind, report: &dyn Report) -> std::io::Result<()> {
	let today = today_string();
	match kind {
		Kind::Dmarc => dmarc::append(data_dir, &today, report.as_dmarc()),
		Kind::TlsRpt => tlsrpt::append(data_dir, &today, report.as_tlsrpt()),
	}
}

fn today_string() -> String {
	let ts = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	crate::dmarc::aggregate::unix_to_day(ts)
}

fn ingest_inner(_data_dir: &Path, kind: Kind, raw: &[u8]) -> Result<Box<dyn Report>, String> {
	let part = mime::find_report_part(raw, kind).map_err(|e| e.to_string())?;
	let (encoding, bytes) = (part.encoding, part.bytes);
	let inflated =
		decompress::inflate_attachment(&bytes, encoding).map_err(|e| e.to_string())?;
	match kind {
		Kind::Dmarc => dmarc::parse(&inflated)
			.map(|r| Box::new(r) as Box<dyn Report>)
			.map_err(|e| e.to_string()),
		Kind::TlsRpt => tlsrpt::parse(&inflated)
			.map(|r| Box::new(r) as Box<dyn Report>)
			.map_err(|e| e.to_string()),
	}
}

/// A parsed report: the contract the hook needs to count and persist it.
trait Report {
	/// Downcast to a DMARC report for the [`dmarc::append`] call.
	fn as_dmarc(&self) -> &dmarc::DmarcReport;
	/// Downcast to a TLS-RPT report for the [`tlsrpt::append`] call.
	fn as_tlsrpt(&self) -> &tlsrpt::TlsReport;
	/// Sanitised org name used as the JSONL filename.
	fn org(&self) -> &str;
	/// Number of rows counted in the failing counter.
	fn failing_count(&self) -> u64;
}

impl Report for dmarc::DmarcReport {
	fn as_dmarc(&self) -> &dmarc::DmarcReport {
		self
	}
	fn as_tlsrpt(&self) -> &tlsrpt::TlsReport {
		// Unreachable: the dispatch in `ingest` only calls `as_tlsrpt` on
		// TLS-RPT reports. Falling back to a default keeps the API
		// uniform without introducing a second trait.
		unreachable!("dmarc report used in tlsrpt path")
	}
	fn org(&self) -> &str {
		dmarc::DmarcReport::org(self)
	}
	fn failing_count(&self) -> u64 {
		dmarc::DmarcReport::failing_count(self)
	}
}

impl Report for tlsrpt::TlsReport {
	fn as_dmarc(&self) -> &dmarc::DmarcReport {
		unreachable!("tlsrpt report used in dmarc path")
	}
	fn as_tlsrpt(&self) -> &tlsrpt::TlsReport {
		self
	}
	fn org(&self) -> &str {
		tlsrpt::TlsReport::org(self)
	}
	fn failing_count(&self) -> u64 {
		tlsrpt::TlsReport::failing_count(self)
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
