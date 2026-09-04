//! Parse TLS-RPT reports (RFC 8460 §4.4).
//!
//! Receivers ship a JSON document with the same shape every time. We use
//! `serde_json` with permissive defaults: unknown fields are dropped, so a
//! new section in the schema does not break ingestion. The size cap is
//! enforced by the caller (`decompress::inflate_attachment`).

use std::path::Path;

/// Why a parsed JSON document was refused.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
	/// The JSON is malformed or has the wrong shape.
	#[error("invalid TLS-RPT JSON: {0}")]
	Invalid(String),
}

/// One parsed TLS-RPT report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsReport {
	/// `organization-name` from the top level.
	#[serde(rename = "organization-name")]
	pub organization_name: String,
	/// `date-range` from the top level.
	#[serde(rename = "date-range")]
	pub date_range: DateRange,
	/// `contact-info` from the top level, if present.
	#[serde(rename = "contact-info", default)]
	pub contact_info: Option<String>,
	/// `report-id` from the top level.
	#[serde(rename = "report-id")]
	pub report_id: String,
	/// `policies` from the top level.
	#[serde(default)]
	pub policies: Vec<Policy>,
}

/// RFC 8460 §4.4 `date-range` block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DateRange {
	/// `start-datetime` as an ISO 8601 string (we keep it verbatim).
	#[serde(rename = "start-datetime")]
	pub start_datetime: String,
	/// `end-datetime` as an ISO 8601 string.
	#[serde(rename = "end-datetime")]
	pub end_datetime: String,
}

/// One entry of `policies`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Policy {
	/// `policy-type` (`sts`, `tlsa`, or `no-policy-found`).
	#[serde(rename = "policy-type")]
	pub policy_type: String,
	/// `policy-domain`.
	#[serde(rename = "policy-domain")]
	pub policy_domain: String,
	/// `summary` block.
	pub summary: Summary,
	/// `failure-details` (absent when every session succeeded).
	#[serde(rename = "failure-details", default)]
	pub failure_details: Vec<Failure>,
}

/// `summary` block of a [`Policy`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Summary {
	/// `total-successful-session-count`.
	#[serde(rename = "total-successful-session-count")]
	pub total_successful_session_count: u64,
	/// `total-failure-session-count`.
	#[serde(rename = "total-failure-session-count")]
	pub total_failure_session_count: u64,
}

/// One entry of `failure-details`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Failure {
	/// `result-type` (an RFC 8460 §4.3 keyword).
	#[serde(rename = "result-type")]
	pub result_type: String,
	/// `sending-mta-ip`.
	#[serde(rename = "sending-mta-ip")]
	pub sending_mta_ip: String,
	/// `receiving-mx-hostname`.
	#[serde(rename = "receiving-mx-hostname")]
	pub receiving_mx_hostname: String,
	/// `failed-session-count`.
	#[serde(rename = "failed-session-count")]
	pub failed_session_count: u64,
}

impl TlsReport {
	/// Sum of `failed-session-count` across every policy and every
	/// failure-detail. This is the number the metrics counter
	/// `tlsrpt_failed_sessions` increments by.
	pub fn failing_count(&self) -> u64 {
		self.policies
			.iter()
			.flat_map(|p| p.failure_details.iter())
			.map(|f| f.failed_session_count)
			.sum()
	}

	/// Sanitised `organization-name` for the JSONL filename.
	pub fn org(&self) -> &str {
		sanitise_org(&self.organization_name)
	}
}

fn sanitise_org(name: &str) -> &str {
	if name.is_empty()
		|| name
			.chars()
			.all(|c| c.is_alphanumeric() || c == '.' || c == '-')
	{
		name
	} else {
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
/// `{data_dir}/reports/tlsrpt/{YYYYMMDD}/{org}.jsonl`. The directory is
/// created on demand.
pub fn append(data_dir: &Path, day: &str, report: &TlsReport) -> std::io::Result<()> {
	let dir = data_dir.join("reports").join("tlsrpt").join(day);
	std::fs::create_dir_all(&dir)?;
	let path = dir.join(format!("{}.jsonl", report.org()));
	use std::io::Write;
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)?;
	let line = serde_json::to_string(report)
		.map_err(|e| std::io::Error::other(format!("serialize tlsrpt report: {e}")))?;
	writeln!(file, "{line}")?;
	Ok(())
}

/// Parse a TLS-RPT report from its (already-decompressed) JSON body.
pub fn parse(json: &[u8]) -> Result<TlsReport, ParseError> {
	serde_json::from_slice(json).map_err(|e| ParseError::Invalid(e.to_string()))
}

#[cfg(test)]
#[path = "tlsrpt_tests.rs"]
mod tests;
