//! Parse TLS-RPT reports (RFC 8460 §4.4).
//!
//! Receivers ship a JSON document with the same shape every time. We use
//! `serde_json` with permissive defaults: unknown fields are dropped, so a
//! new section in the schema does not break ingestion. The size cap is
//! enforced by the caller (`decompress::inflate_attachment`).

use std::path::Path;

use super::bounds::{self, MAX_KEYWORD, MAX_TEXT};

/// Most `policies` entries kept from one report. A sender reports one entry
/// per policy domain and policy type; a typical report about this server
/// names a handful. Documents with more entries have the overflow dropped
/// and [`TlsReport::truncated`] set to `true`.
pub const MAX_POLICIES: usize = 1_000;

/// Most `failure-details` entries kept from one policy. RFC 8460 groups
/// failures by result type, sending IP and receiving MX, so even a bad day
/// produces tens. A policy with more is truncated and the parent report is
/// marked.
pub const MAX_FAILURE_DETAILS: usize = 1_000;

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
	/// `policies` from the top level, capped at [`MAX_POLICIES`].
	/// When the document carried more entries, [`Self::truncated`] is
	/// `true` and only the first [`MAX_POLICIES`] survived.
	pub policies: Vec<Policy>,
	/// `true` when one or more policies or failure-details were dropped
	/// because the document exceeded the per-list cap.
	#[serde(default)]
	pub truncated: bool,
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
	/// `failure-details` (absent when every session succeeded), capped
	/// at [`MAX_FAILURE_DETAILS`]. When the policy carried more entries
	/// the parent report's [`TlsReport::truncated`] is `true`.
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
			.fold(0u64, |total, f| {
				total.saturating_add(f.failed_session_count)
			})
	}

	/// File-name component derived from `organization-name`. The mapping
	/// (alphanumerics, `.` and `-` survive; everything else becomes `_`;
	/// capped at 64 bytes; pure-dot names become `unknown`) is shared
	/// with the DMARC parser via the private `bounds::file_component`.
	pub fn org(&self) -> String {
		bounds::file_component(&self.organization_name)
	}

	/// Cap every free-text field copied from the document, see
	/// [`bounds::cap_text`].
	fn cap_fields(&mut self) {
		bounds::cap_in_place(&mut self.organization_name, MAX_TEXT);
		bounds::cap_in_place(&mut self.report_id, MAX_TEXT);
		if let Some(contact) = self.contact_info.as_mut() {
			bounds::cap_in_place(contact, MAX_TEXT);
		}
		bounds::cap_in_place(&mut self.date_range.start_datetime, MAX_KEYWORD);
		bounds::cap_in_place(&mut self.date_range.end_datetime, MAX_KEYWORD);
		for policy in &mut self.policies {
			bounds::cap_in_place(&mut policy.policy_type, MAX_KEYWORD);
			bounds::cap_in_place(&mut policy.policy_domain, MAX_TEXT);
			for failure in &mut policy.failure_details {
				bounds::cap_in_place(&mut failure.result_type, MAX_KEYWORD);
				bounds::cap_in_place(&mut failure.sending_mta_ip, MAX_KEYWORD);
				bounds::cap_in_place(&mut failure.receiving_mx_hostname, MAX_TEXT);
			}
		}
	}
}

/// Persist the JSONL line under
/// `{data_dir}/reports/tlsrpt/{YYYYMMDD}/{org}.jsonl`, where `{org}` is
/// [`TlsReport::org`].
pub fn append(data_dir: &Path, day: &str, report: &TlsReport) -> std::io::Result<()> {
	super::store::append(data_dir, super::Kind::TlsRpt, day, &report.org(), report)
}

#[derive(serde::Deserialize)]
struct RawTlsReport {
	#[serde(rename = "organization-name")]
	organization_name: String,
	#[serde(rename = "date-range")]
	date_range: DateRange,
	#[serde(rename = "contact-info", default)]
	contact_info: Option<String>,
	#[serde(rename = "report-id")]
	report_id: String,
	#[serde(default, deserialize_with = "capped_policies")]
	policies: Vec<RawPolicy>,
}

#[derive(serde::Deserialize)]
struct RawPolicy {
	#[serde(rename = "policy-type")]
	policy_type: String,
	#[serde(rename = "policy-domain")]
	policy_domain: String,
	summary: Summary,
	#[serde(
		rename = "failure-details",
		default,
		deserialize_with = "capped_failures"
	)]
	failure_details: Vec<Failure>,
}

/// Parse a TLS-RPT report from its (already-decompressed) JSON body.
pub fn parse(json: &[u8]) -> Result<TlsReport, ParseError> {
	let raw: RawTlsReport = serde_json::from_slice(json)
		.map_err(|e| ParseError::Invalid(bounds::cap_text(&e.to_string(), MAX_TEXT)))?;
	let (policies_overflow, raw_policies) = bounds::truncate(raw.policies, MAX_POLICIES);
	let mut truncated = policies_overflow;
	let mut policies = Vec::with_capacity(raw_policies.len());
	for raw_policy in raw_policies {
		let (failures_overflow, failure_details) =
			bounds::truncate(raw_policy.failure_details, MAX_FAILURE_DETAILS);
		if failures_overflow {
			truncated = true;
		}
		policies.push(Policy {
			policy_type: raw_policy.policy_type,
			policy_domain: raw_policy.policy_domain,
			summary: raw_policy.summary,
			failure_details,
		});
	}
	let mut report = TlsReport {
		organization_name: raw.organization_name,
		date_range: raw.date_range,
		contact_info: raw.contact_info,
		report_id: raw.report_id,
		policies,
		truncated,
	};
	report.cap_fields();
	Ok(report)
}

fn capped_policies<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<RawPolicy>, D::Error> {
	bounds::capped_seq(deserializer, MAX_POLICIES)
}

fn capped_failures<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<Failure>, D::Error> {
	bounds::capped_seq(deserializer, MAX_FAILURE_DETAILS)
}

#[cfg(test)]
#[path = "tlsrpt_tests.rs"]
mod tests;
