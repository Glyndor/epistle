//! Parse DMARC aggregate reports (RFC 7489 Appendix C).
//!
//! The XML shape is fixed by the standard. We use `quick_xml::de` with
//! permissive defaults: unknown elements are silently dropped, which is
//! what every receiver-side parser does and what the spec demands for
//! forward compatibility. The size cap is enforced by the caller
//! (`decompress::inflate_attachment`) before these bytes ever arrive.

use std::path::Path;

use serde::Deserialize;

use super::bounds::{self, MAX_KEYWORD, MAX_TEXT};

/// Most `<record>` entries kept from one report. Google and Microsoft
/// rarely send more than a few hundred; 10 000 is one order of magnitude
/// above the largest realistic report and still small enough to keep the
/// deserialiser bounded.
pub const MAX_ROWS: usize = 10_000;

/// Why a parsed document was refused, beyond "wrong shape".
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
	/// The XML is malformed or has the wrong shape.
	#[error("invalid DMARC aggregate XML: {0}")]
	Invalid(String),
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
	/// Every `<record>` element of the document, capped at [`MAX_ROWS`].
	/// When the document carried more entries, [`Self::truncated`] is
	/// `true` and only the first [`MAX_ROWS`] survived.
	pub records: Vec<Row>,
	/// `true` when one or more `<record>` entries were dropped because
	/// the document exceeded [`MAX_ROWS`].
	#[serde(default)]
	pub truncated: bool,
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
			.fold(0u64, |total, row| total.saturating_add(row.count))
	}

	/// File-name component derived from `org_name`. The mapping (alphanumerics,
	/// `.` and `-` survive; everything else becomes `_`; capped at 64 bytes;
	/// pure-dot names become `unknown`) is shared with the TLS-RPT parser
	/// via the private `bounds::file_component`.
	pub fn org(&self) -> String {
		bounds::file_component(&self.org_name)
	}
}

/// True when the row would have triggered DMARC enforcement (the receiver
/// did quarantine/reject, or both SPF and DKIM failed).
fn is_failing(row: &Row) -> bool {
	let disposition_failing = matches!(row.disposition.as_str(), "quarantine" | "reject");
	let auth_failing = row.dkim == "fail" && row.spf == "fail";
	disposition_failing || auth_failing
}

/// Persist the JSONL line under
/// `{data_dir}/reports/dmarc/{YYYYMMDD}/{org}.jsonl`, where `{org}` is
/// [`DmarcReport::org`].
pub fn append(data_dir: &Path, day: &str, report: &DmarcReport) -> std::io::Result<()> {
	super::store::append(data_dir, super::Kind::Dmarc, day, &report.org(), report)
}

#[derive(Deserialize)]
struct RawReport {
	#[serde(default, rename = "report_metadata")]
	report_metadata: Option<RawReportMetadata>,
	#[serde(default, rename = "policy_published")]
	policy_published: Option<RawPolicyPublished>,
	#[serde(default, rename = "record", deserialize_with = "capped_records")]
	record: Vec<RawRecord>,
}

fn capped_records<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<RawRecord>, D::Error> {
	bounds::capped_seq(deserializer, MAX_ROWS)
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
	.map_err(|e| ParseError::Invalid(bounds::cap_text(&e.to_string(), MAX_TEXT)))?;
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
	let (truncated, raw_records) = bounds::truncate(raw.record, MAX_ROWS);
	let mut records = Vec::with_capacity(raw_records.len());
	for rec in raw_records {
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
			source_ip: keyword(row.source_ip),
			count: row.count.unwrap_or(0),
			disposition: keyword(eval.disposition),
			dkim: keyword(eval.dkim),
			spf: keyword(eval.spf),
			header_from: text(ids.header_from),
		});
	}
	Ok(DmarcReport {
		org_name: text(meta.org_name),
		email: meta.email.map(|e| bounds::cap_text(&e, MAX_TEXT)),
		report_id: text(meta.report_id),
		date_range: DateRange {
			begin: range.begin.unwrap_or(0),
			end: range.end.unwrap_or(0),
		},
		policy_published: PolicyPublished {
			domain: text(pub_.domain),
			p: pub_
				.p
				.map_or_else(|| "none".into(), |p| bounds::cap_text(&p, MAX_KEYWORD)),
			sp: pub_.sp.map(|sp| bounds::cap_text(&sp, MAX_KEYWORD)),
			pct: pub_.pct.unwrap_or(100),
		},
		records,
		truncated,
	})
}

/// A free-text field, absent as empty, capped at [`MAX_TEXT`].
fn text(value: Option<String>) -> String {
	value.map_or_else(String::new, |v| bounds::cap_text(&v, MAX_TEXT))
}

/// A keyword-like field, absent as empty, capped at [`MAX_KEYWORD`].
fn keyword(value: Option<String>) -> String {
	value.map_or_else(String::new, |v| bounds::cap_text(&v, MAX_KEYWORD))
}

#[cfg(test)]
#[path = "dmarc_tests.rs"]
mod tests;
