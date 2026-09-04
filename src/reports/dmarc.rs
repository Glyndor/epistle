//! Parse DMARC aggregate reports (RFC 7489 Appendix C).
//!
//! The XML shape is fixed by the standard. We use `quick_xml::de` with
//! permissive defaults: unknown elements are silently dropped, which is
//! what every receiver-side parser does and what the spec demands for
//! forward compatibility. The size cap is enforced by the caller
//! (`decompress::inflate_attachment`) before these bytes ever arrive.

use std::path::Path;

use serde::Deserialize;

/// Refuse a document with more than this many rows. Google and Microsoft
/// rarely send more than a few hundred in a single report; an order of
/// magnitude above that is still safe to ingest but a hostile report
/// could try to balloon our memory.
pub const MAX_ROWS: usize = 10_000;

/// Why a parsed document was refused, beyond "wrong shape".
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
	/// The XML is malformed or has the wrong shape.
	#[error("invalid DMARC aggregate XML: {0}")]
	Invalid(String),
	/// The document has more than [`MAX_ROWS`] records.
	#[error("DMARC aggregate report has too many records (>{MAX_ROWS})")]
	TooManyRows,
}

/// One parsed DMARC aggregate report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DmarcReport {
	/// `org_name` from `report_metadata`. Sanitised for filename use by
	/// [`DmarcReport::org`].
	pub org_name: String,
	/// `email` from `report_metadata`, if present.
	pub email: Option<String>,
	/// `report_id` from `report_metadata`.
	pub report_id: String,
	/// `date_range` from `report_metadata` (begin/end Unix seconds).
	pub date_range: DateRange,
	/// `policy_published` from `policy_published`.
	pub policy_published: PolicyPublished,
	/// Every `<record>` element of the document.
	pub records: Vec<Row>,
}

/// `<date_range>` block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DateRange {
	/// Unix seconds the period starts.
	pub begin: u64,
	/// Unix seconds the period ends.
	pub end: u64,
}

/// `<policy_published>` block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyPublished {
	/// The `<domain>` element.
	pub domain: String,
	/// The `<p>` element.
	pub p: String,
	/// The `<sp>` element when the document distinguishes subdomain policy.
	pub sp: Option<String>,
	/// The `<pct>` element (1..=100).
	pub pct: u8,
}

/// One `<record>` element of the document.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Row {
	/// `<source_ip>`.
	pub source_ip: String,
	/// `<count>`.
	pub count: u64,
	/// `<disposition>` under `<policy_evaluated>`.
	pub disposition: String,
	/// `<dkim>` under `<policy_evaluated>`.
	pub dkim: String,
	/// `<spf>` under `<policy_evaluated>`.
	pub spf: String,
	/// `<header_from>` under `<identifiers>`.
	pub header_from: String,
}

impl DmarcReport {
	/// Sum `count` over the rows that fail authentication: a disposition
	/// of `quarantine` or `reject`, or both `dkim` and `spf` `fail`. This is
	/// what the metrics counter `dmarc_report_rows_failing` adds to its
	/// process-wide total.
	pub fn failing_count(&self) -> u64 {
		self.records
			.iter()
			.filter(|row| is_failing(row))
			.map(|row| row.count)
			.sum()
	}

	/// Sanitised `org_name` for use as a JSONL file name.
	pub fn org(&self) -> &str {
		sanitise_org(&self.org_name)
	}
}

/// True when the row would have triggered DMARC enforcement (the receiver
/// did quarantine/reject, or both SPF and DKIM failed).
fn is_failing(row: &Row) -> bool {
	let disposition_failing = matches!(row.disposition.as_str(), "quarantine" | "reject");
	let auth_failing = row.dkim == "fail" && row.spf == "fail";
	disposition_failing || auth_failing
}

fn sanitise_org(name: &str) -> &str {
	// The org_name is human-set; the JSONL filename lives under
	// data_dir/reports/dmarc/{YYYYMMDD}/. We borrow the same approach as
	// `dmarc::aggregate::record_path`: anything that would not be safe as a
	// filename has to be normalised. For the org string itself we keep the
	// raw value in the JSONL and only sanitise on the filename side, so a
	// slash in an org name does not change the persisted record.
	if name.is_empty()
		|| name
			.chars()
			.all(|c| c.is_alphanumeric() || c == '.' || c == '-')
	{
		name
	} else {
		// Allocate once at the boundary, then borrow it back into the
		// caller. The caller never outlives this scope.
		Box::leak(
			name.chars()
				.map(|c| {
					if c.is_alphanumeric() || c == '.' || c == '-' {
						c
					} else {
						'_'
					}
				})
				.collect::<String>()
				.into_boxed_str(),
		)
	}
}

/// Persist the JSONL line under
/// `{data_dir}/reports/dmarc/{YYYYMMDD}/{org}.jsonl`. The directory is
/// created on demand; a missing data_dir is propagated as an error.
pub fn append(data_dir: &Path, day: &str, report: &DmarcReport) -> std::io::Result<()> {
	let dir = data_dir.join("reports").join("dmarc").join(day);
	std::fs::create_dir_all(&dir)?;
	let path = dir.join(format!("{}.jsonl", report.org()));
	use std::io::Write;
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)?;
	let line = serde_json::to_string(report)
		.map_err(|e| std::io::Error::other(format!("serialize dmarc report: {e}")))?;
	writeln!(file, "{line}")?;
	Ok(())
}

#[derive(Deserialize)]
struct RawReport {
	#[serde(default, rename = "report_metadata")]
	report_metadata: Option<RawReportMetadata>,
	#[serde(default, rename = "policy_published")]
	policy_published: Option<RawPolicyPublished>,
	#[serde(default, rename = "record")]
	record: Vec<RawRecord>,
}

#[derive(Deserialize)]
struct RawReportMetadata {
	#[serde(default, rename = "org_name")]
	org_name: Option<String>,
	#[serde(default, rename = "email")]
	email: Option<String>,
	#[serde(default, rename = "report_id")]
	report_id: Option<String>,
	#[serde(default, rename = "date_range")]
	date_range: Option<RawDateRange>,
}

#[derive(Deserialize)]
struct RawDateRange {
	#[serde(default, rename = "begin")]
	begin: Option<u64>,
	#[serde(default, rename = "end")]
	end: Option<u64>,
}

#[derive(Deserialize)]
struct RawPolicyPublished {
	#[serde(default, rename = "domain")]
	domain: Option<String>,
	#[serde(default, rename = "p")]
	p: Option<String>,
	#[serde(default, rename = "sp")]
	sp: Option<String>,
	#[serde(default, rename = "pct")]
	pct: Option<u8>,
}

#[derive(Deserialize)]
struct RawRecord {
	#[serde(default, rename = "row")]
	row: Option<RawRow>,
	#[serde(default, rename = "identifiers")]
	identifiers: Option<RawIdentifiers>,
}

#[derive(Deserialize)]
struct RawRow {
	#[serde(default, rename = "source_ip")]
	source_ip: Option<String>,
	#[serde(default, rename = "count")]
	count: Option<u64>,
	#[serde(default, rename = "policy_evaluated")]
	policy_evaluated: Option<RawPolicyEvaluated>,
}

#[derive(Deserialize)]
struct RawPolicyEvaluated {
	#[serde(default, rename = "disposition")]
	disposition: Option<String>,
	#[serde(default, rename = "dkim")]
	dkim: Option<String>,
	#[serde(default, rename = "spf")]
	spf: Option<String>,
}

#[derive(Deserialize)]
struct RawIdentifiers {
	#[serde(default, rename = "header_from")]
	header_from: Option<String>,
}

/// Parse a DMARC aggregate report from its (already-decompressed) XML body.
pub fn parse(xml: &[u8]) -> Result<DmarcReport, ParseError> {
	let raw: RawReport = quick_xml::de::from_str(
		std::str::from_utf8(xml)
			.map_err(|e| ParseError::Invalid(format!("xml is not utf-8: {e}")))?,
	)
	.map_err(|e| ParseError::Invalid(e.to_string()))?;
	if raw.record.len() > MAX_ROWS {
		return Err(ParseError::TooManyRows);
	}
	let meta = raw.report_metadata.unwrap_or(RawReportMetadata {
		org_name: None,
		email: None,
		report_id: None,
		date_range: None,
	});
	let range = meta.date_range.unwrap_or(RawDateRange {
		begin: None,
		end: None,
	});
	let pub_ = raw.policy_published.unwrap_or(RawPolicyPublished {
		domain: None,
		p: None,
		sp: None,
		pct: None,
	});
	let mut records = Vec::with_capacity(raw.record.len());
	for rec in raw.record {
		let row = rec.row.unwrap_or(RawRow {
			source_ip: None,
			count: None,
			policy_evaluated: None,
		});
		let eval = row.policy_evaluated.unwrap_or(RawPolicyEvaluated {
			disposition: None,
			dkim: None,
			spf: None,
		});
		let ids = rec
			.identifiers
			.unwrap_or(RawIdentifiers { header_from: None });
		records.push(Row {
			source_ip: row.source_ip.unwrap_or_default(),
			count: row.count.unwrap_or(0),
			disposition: eval.disposition.unwrap_or_default(),
			dkim: eval.dkim.unwrap_or_default(),
			spf: eval.spf.unwrap_or_default(),
			header_from: ids.header_from.unwrap_or_default(),
		});
	}
	Ok(DmarcReport {
		org_name: meta.org_name.unwrap_or_default(),
		email: meta.email,
		report_id: meta.report_id.unwrap_or_default(),
		date_range: DateRange {
			begin: range.begin.unwrap_or(0),
			end: range.end.unwrap_or(0),
		},
		policy_published: PolicyPublished {
			domain: pub_.domain.unwrap_or_default(),
			p: pub_.p.unwrap_or_else(|| "none".into()),
			sp: pub_.sp,
			pct: pub_.pct.unwrap_or(100),
		},
		records,
	})
}

#[cfg(test)]
#[path = "dmarc_tests.rs"]
mod tests;
