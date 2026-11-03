//! Entry point for the fuzz target of ARF feedback reports (see
//! `crate::fuzzing`): an inbound report read by [`super::parse`], and a
//! report built by [`super::build`] from the values an inbound complaint
//! carries, which nobody authenticated.

use std::time::{Duration, UNIX_EPOCH};

use super::{FeedbackType, Report, build, parse};

/// The fields of the machine-readable part [`build`] writes, in order.
const FIELDS: [&str; 7] = [
	"Feedback-Type",
	"User-Agent",
	"Version",
	"Original-Mail-From",
	"Arrival-Date",
	"Reported-Domain",
	"Source-IP",
];

/// Parse `raw` as an inbound report, then build one whose sender, source IP
/// and reported message come from `raw` (split at NUL bytes).
///
/// # Panics
///
/// When a parsed field spans lines or is not trimmed, or a value from the
/// complaint adds, drops or reorders a field of the built report.
pub(crate) fn report_for_fuzzing(raw: &[u8]) {
	if let Some(report) = parse(raw) {
		assert!(!report.feedback_type.is_empty(), "empty Feedback-Type");
		for value in [
			Some(&report.feedback_type),
			report.original_mail_from.as_ref(),
			report.source_ip.as_ref(),
			report.reported_domain.as_ref(),
			report.arrival_date.as_ref(),
		]
		.into_iter()
		.flatten()
		{
			assert!(!value.contains('\n'), "a field spans lines");
			assert_eq!(value.trim(), value, "an untrimmed field");
		}
	}
	let text = String::from_utf8_lossy(raw);
	let mut parts = text.splitn(3, '\0');
	let mail_from = parts.next().unwrap_or_default();
	let source_ip = parts.next().unwrap_or_default();
	let message = parts.next().unwrap_or_default();
	let built = build(
		"mx.example.org",
		&Report {
			report_to: "abuse@example.net",
			feedback_type: FeedbackType::Abuse,
			original_mail_from: mail_from,
			source_ip: Some(source_ip),
			reported_message: message.as_bytes(),
		},
		UNIX_EPOCH + Duration::from_secs(1_800_000_000),
	);
	let data = String::from_utf8_lossy(&built.data);
	let start = data
		.find("\r\nContent-Type: message/feedback-report\r\n\r\n")
		.expect("the built report has a feedback part")
		+ "\r\nContent-Type: message/feedback-report\r\n\r\n".len();
	let block = &data[start..];
	let block = &block[..block.find("\r\n\r\n").expect("the feedback part ends")];
	let names: Vec<&str> = block
		.split("\r\n")
		.map(|line| line.split_once(':').map_or(line, |(name, _)| name))
		.collect();
	assert_eq!(names, FIELDS, "a complaint value changed the report fields");
	if let Some(again) = parse(&built.data) {
		assert_eq!(again.feedback_type, "abuse", "Feedback-Type forged");
	}
}
