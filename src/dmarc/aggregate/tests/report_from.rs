//! A queued report comes from the configured address, keeps the server's
//! envelope sender, and quotes the policy the journal recorded.

use std::io::Read;

use base64::Engine;

use super::base::{build_sender, dns_with_dmarc, sample_record};
use super::*;
use crate::smtp::sink::MemorySink;

/// The XML a queued report message carries.
fn attached_xml(message: &[u8]) -> String {
	let text = std::str::from_utf8(message).expect("utf-8");
	let start = text
		.find("Content-Disposition: attachment")
		.and_then(|at| text[at..].find("\r\n\r\n").map(|end| at + end + 4))
		.expect("attachment part");
	let encoded: String = text[start..]
		.lines()
		.take_while(|line| !line.is_empty())
		.collect();
	let gzip = base64::engine::general_purpose::STANDARD
		.decode(encoded)
		.expect("base64");
	let mut xml = String::new();
	flate2::read::GzDecoder::new(gzip.as_slice())
		.read_to_string(&mut xml)
		.expect("gzip");
	xml
}

#[tokio::test]
async fn the_report_comes_from_the_configured_address_on_the_usual_envelope() {
	let dir = tempfile::tempdir().expect("tempdir");
	record_delivery(dir.path(), "20240101", &sample_record("example.org"));
	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let mut sender = build_sender(dir.path(), &dns, &sink);
	sender.org_email = "dmarc-reports@reporter.example";
	flush_pending(&sender, "20240102").await;

	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "postmaster@mail.reporter.example");
	let text = String::from_utf8_lossy(&messages[0].data);
	let from: Vec<&str> = text
		.lines()
		.filter(|line| line.to_ascii_lowercase().starts_with("from:"))
		.collect();
	assert_eq!(from, ["From: dmarc-reports@reporter.example"], "{text}");
	let xml = attached_xml(&messages[0].data);
	assert!(
		xml.contains("<email>dmarc-reports@reporter.example</email>"),
		"{xml}"
	);
}

#[tokio::test]
async fn the_report_quotes_the_policy_the_journal_recorded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut record = sample_record("example.org");
	record.published_policy = "quarantine".to_string();
	record.published_subdomain_policy = "none".to_string();
	record.pct = 25;
	record_delivery(dir.path(), "20240101", &record);
	let dns = dns_with_dmarc("example.org", "quarantine");
	let sink = MemorySink::new();
	flush_pending(&build_sender(dir.path(), &dns, &sink), "20240102").await;

	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let xml = attached_xml(&messages[0].data);
	assert!(
		xml.contains(
			"<domain>example.org</domain>\n    <p>quarantine</p>\n    <sp>none</sp>\n    <pct>25</pct>"
		),
		"{xml}"
	);
}
