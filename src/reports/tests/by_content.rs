//! A message is read by what it carries, not by the mailbox it came to: a
//! TLS-RPT report sent to `postmaster@` is a TLS-RPT report, and a message
//! with no report part is not a report, which is not a failure.

use super::*;
use crate::cli::trace::capture::{Capture, CapturedEvent};
use base64::Engine;
use std::io::Write;
use tracing_subscriber::layer::SubscriberExt;

const TLS_JSON: &str = r#"{"organization-name":"Example Reporter","date-range":{"start-datetime":"2026-01-01T00:00:00Z","end-datetime":"2026-01-02T00:00:00Z"},"contact-info":"smtp-tls-reporting@example.net","report-id":"tls-1","policies":[{"policy":{"policy-type":"sts","policy-domain":"example.org"},"summary":{"total-successful-session-count":3,"total-failure-session-count":0}}]}"#;

const DMARC_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata><org_name>reporter.example</org_name><report_id>dmarc-1</report_id><date_range><begin>0</begin><end>1</end></date_range></report_metadata>
  <policy_published><domain>example.org</domain><p>reject</p><pct>100</pct></policy_published>
  <record><row><source_ip>203.0.113.7</source_ip><count>2</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.org</header_from></identifiers></record>
</feedback>
"#;

fn gzip(bytes: &[u8]) -> Vec<u8> {
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(bytes).expect("write");
	encoder.finish().expect("finish")
}

/// A zip with one stored entry.
fn zip(name: &str, payload: &[u8]) -> Vec<u8> {
	let mut crc = flate2::Crc::new();
	crc.update(payload);
	let (crc, size) = (
		crc.sum().to_le_bytes(),
		(payload.len() as u32).to_le_bytes(),
	);
	let mut local = vec![0; 30];
	local[..4].copy_from_slice(b"PK\x03\x04");
	local[4..6].copy_from_slice(&20u16.to_le_bytes());
	local[14..18].copy_from_slice(&crc);
	local[18..22].copy_from_slice(&size);
	local[22..26].copy_from_slice(&size);
	local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
	let mut central = vec![0; 46];
	central[..4].copy_from_slice(b"PK\x01\x02");
	central[4..6].copy_from_slice(&20u16.to_le_bytes());
	central[6..8].copy_from_slice(&20u16.to_le_bytes());
	central[16..20].copy_from_slice(&crc);
	central[20..24].copy_from_slice(&size);
	central[24..28].copy_from_slice(&size);
	central[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
	let mut bytes = local;
	bytes.extend_from_slice(name.as_bytes());
	bytes.extend_from_slice(payload);
	let central_offset = bytes.len() as u32;
	central.extend_from_slice(name.as_bytes());
	let mut eocd = vec![0; 22];
	eocd[..4].copy_from_slice(b"PK\x05\x06");
	eocd[8..10].copy_from_slice(&1u16.to_le_bytes());
	eocd[10..12].copy_from_slice(&1u16.to_le_bytes());
	eocd[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
	eocd[16..20].copy_from_slice(&central_offset.to_le_bytes());
	bytes.extend_from_slice(&central);
	bytes.extend_from_slice(&eocd);
	bytes
}

/// A multipart message: an explanatory text part, then `parts` as
/// `(content type, transfer encoding, body)`.
fn message(parts: &[(&str, &str, String)]) -> Vec<u8> {
	let mut out = String::from(
		"From: reporter@example.net\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nreport attached\r\n",
	);
	for (content_type, encoding, body) in parts {
		out.push_str(&format!(
			"--B\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n"
		));
	}
	out.push_str("--B--\r\n");
	out.into_bytes()
}

fn b64(bytes: &[u8]) -> String {
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

struct Outcome {
	events: Vec<CapturedEvent>,
	counters: std::collections::BTreeMap<String, u64>,
	dir: tempfile::TempDir,
}

impl Outcome {
	fn counter(&self, name: &str) -> u64 {
		self.counters.get(name).copied().unwrap_or(0)
	}

	fn stored(&self, kind: &str) -> bool {
		self.dir.path().join("reports").join(kind).exists()
	}

	fn failures(&self) -> usize {
		self.events
			.iter()
			.filter(|event| {
				event.fields.get("message").map(String::as_str) == Some("report ingestion failed")
			})
			.count()
	}
}

/// Ingest `data` the way the delivery hook does, for a verified sender.
fn run(data: Vec<u8>) -> Outcome {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = Capture::default();
	let events = capture.events.clone();
	let guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Metrics::new();
	let message = AcceptedMessage {
		recipients: vec!["postmaster@mail.example.org".into()],
		data,
		tlsrpt_verified: true,
		..AcceptedMessage::default()
	};
	ingest(dir.path(), &message, Some(&metrics));
	drop(guard);
	let events = events.lock().expect("capture").clone();
	let counters = metrics
		.snapshot()
		.into_iter()
		.map(|(name, value)| (name.to_string(), value))
		.collect();
	Outcome {
		events,
		counters,
		dir,
	}
}

fn assert_tlsrpt_only(outcome: &Outcome) {
	assert_eq!(outcome.counter("tlsrpt_reports_ingested"), 1);
	assert_eq!(outcome.counter("dmarc_reports_ingested"), 0);
	assert_eq!(outcome.counter("reports_dropped"), 0);
	assert_eq!(outcome.failures(), 0, "no reader may fail on it");
	assert!(outcome.stored("tlsrpt") && !outcome.stored("dmarc"));
}

fn assert_dmarc_only(outcome: &Outcome) {
	assert_eq!(outcome.counter("dmarc_reports_ingested"), 1);
	assert_eq!(outcome.counter("tlsrpt_reports_ingested"), 0);
	assert_eq!(outcome.counter("reports_dropped"), 0);
	assert_eq!(outcome.failures(), 0);
	assert!(outcome.stored("dmarc") && !outcome.stored("tlsrpt"));
}

#[test]
fn a_gzip_tlsrpt_report_is_read_as_tlsrpt() {
	let gz = gzip(TLS_JSON.as_bytes());
	let outcome = run(message(&[("application/tlsrpt+gzip", "base64", b64(&gz))]));
	assert_tlsrpt_only(&outcome);
}

#[test]
fn a_plain_json_tlsrpt_report_is_read_as_tlsrpt() {
	let outcome = run(message(&[(
		"application/tlsrpt+json",
		"7bit",
		TLS_JSON.to_string(),
	)]));
	assert_tlsrpt_only(&outcome);
}

#[test]
fn a_tlsrpt_json_packed_as_a_generic_gzip_is_still_tlsrpt() {
	let gz = gzip(TLS_JSON.as_bytes());
	let outcome = run(message(&[("application/gzip", "base64", b64(&gz))]));
	assert_tlsrpt_only(&outcome);
}

#[test]
fn a_gzip_dmarc_report_is_read_as_dmarc() {
	let gz = gzip(DMARC_XML.as_bytes());
	let outcome = run(message(&[("application/gzip", "base64", b64(&gz))]));
	assert_dmarc_only(&outcome);
}

#[test]
fn a_zip_dmarc_report_is_read_as_dmarc() {
	let zip = zip("report.xml", DMARC_XML.as_bytes());
	let outcome = run(message(&[("application/zip", "base64", b64(&zip))]));
	assert_dmarc_only(&outcome);
}

#[test]
fn a_bare_xml_dmarc_report_is_read_as_dmarc() {
	let outcome = run(message(&[(
		"application/xml",
		"7bit",
		DMARC_XML.to_string(),
	)]));
	assert_dmarc_only(&outcome);
}

#[test]
fn xml_that_is_not_a_dmarc_feedback_is_not_a_report() {
	let outcome = run(message(&[(
		"text/xml",
		"7bit",
		"<?xml version=\"1.0\"?><note>hello</note>".to_string(),
	)]));
	assert_eq!(outcome.counter("reports_dropped"), 0);
	assert_eq!(outcome.failures(), 0);
	assert!(!outcome.stored("dmarc"));
}

#[test]
fn a_message_with_no_report_part_is_logged_once_at_info_with_its_types() {
	let outcome = run(message(&[(
		"text/html",
		"7bit",
		"<p>hello</p>".to_string(),
	)]));
	let lines: Vec<&CapturedEvent> = outcome
		.events
		.iter()
		.filter(|event| {
			event.fields.get("message").map(String::as_str) == Some("message is not a report")
		})
		.collect();
	assert_eq!(lines.len(), 1, "logged once");
	assert_eq!(lines[0].level, tracing::Level::INFO);
	assert_eq!(lines[0].fields["content_types"], "text/plain, text/html");
	assert_eq!(outcome.events.len(), 1, "and nothing else is logged");
	assert_eq!(outcome.counter("reports_dropped"), 0, "it is not a failure");
	assert!(!outcome.stored("dmarc") && !outcome.stored("tlsrpt"));
}

#[test]
fn a_plain_message_without_content_type_is_not_a_report() {
	let outcome = run(b"From: someone@example.net\r\nSubject: hi\r\n\r\nhello\r\n".to_vec());
	assert_eq!(outcome.failures(), 0);
	assert_eq!(outcome.counter("reports_dropped"), 0);
	assert_eq!(outcome.events.len(), 1);
	assert_eq!(outcome.events[0].level, tracing::Level::INFO);
}
