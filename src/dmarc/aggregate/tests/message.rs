//! Item 2: a well-formed DMARC aggregate report message (RFC 7489 §7.2.1.1).
//!
//! The outgoing report message carries `Date:`, a unique `Message-ID:` in
//! the reporting hostname, the `From:`, `To:`, the RFC-prescribed subject,
//! and the gzip XML attachment named
//! `<receiver>!<policy domain>!<begin>!<end>.xml.gz`.

use std::io::Read;

use base64::Engine;

use super::super::super::report::build_email;
use super::super::super::report::build_xml;
use super::DeliveryRecord;

fn sample_records() -> Vec<DeliveryRecord> {
	vec![DeliveryRecord {
		timestamp: 1_700_000_000,
		source_ip: "1.2.3.4".to_string(),
		envelope_from: "example.org".to_string(),
		header_from: "example.org".to_string(),
		spf: "pass".to_string(),
		dkim: "pass".to_string(),
		dkim_domain: "example.org".to_string(),
		dmarc: "pass".to_string(),
		disposition: "none".to_string(),
		policy_domain: "example.org".to_string(),
		published_policy: "reject".to_string(),
		pct: 100,
	}]
}

#[test]
fn report_message_carries_rfc_5322_headers_and_attachment_filename() {
	let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
	let attachment = build_xml(
		"Org",
		"admin@org.example",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"sender.example",
		&sample_records(),
	);
	let body = build_email(
		"sender.example",
		"reports@collector.example",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"mail.reporter.example",
		"mail.reporter.example",
		now,
		&attachment,
		true,
	);
	let text = std::str::from_utf8(&body).expect("utf-8 message");

	// Date: header.
	let date = text
		.lines()
		.find(|line| line.starts_with("Date: "))
		.expect("Date: header present");
	assert_eq!(date, "Date: Tue, 14 Nov 2023 22:13:20 +0000");

	// Message-ID: must be unique and in the reporting hostname.
	let message_id = text
		.lines()
		.find(|line| line.starts_with("Message-ID: "))
		.expect("Message-ID: header present");
	assert_eq!(message_id, "Message-ID: <r1@mail.reporter.example>");

	// From: / To: / Subject: per RFC 7489 §7.2.1.1.
	assert!(text.contains("From: postmaster@mail.reporter.example\r\n"));
	assert!(text.contains("To: reports@collector.example\r\n"));
	assert!(
		text.contains(
			"Subject: Report Domain: sender.example \
			 Submitter: mail.reporter.example Report-ID: <r1>\r\n"
		),
		"subject must follow RFC 7489 §7.2.1.1 wording: {text}"
	);

	// Attachment filename: <receiver>!<policy domain>!<begin>!<end>.xml.gz.
	let expected_filename = "mail.reporter.example!sender.example!1700000000!1700086400.xml.gz";
	assert!(
		text.contains(&format!(
			"Content-Disposition: attachment; filename=\"{expected_filename}\"\r\n"
		)),
		"attachment filename must follow the RFC 7489 §7.2.1.1 convention: {text}"
	);
	assert!(text.contains(&format!("name=\"{expected_filename}\"")));
}

#[test]
fn attachment_payload_decodes_to_valid_gzip_xml() {
	let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
	let attachment = build_xml(
		"Org",
		"admin@org.example",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"example.org",
		&sample_records(),
	);
	let body = build_email(
		"example.org",
		"reports@example.org",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"reporter.example",
		"reporter.example",
		now,
		&attachment,
		true,
	);
	let text = std::str::from_utf8(&body).expect("utf-8");
	let attachment_start = text
		.find("Content-Disposition: attachment")
		.and_then(|at| text[at..].find("\r\n\r\n").map(|end| at + end + 4))
		.expect("attachment part");
	let encoded: String = text[attachment_start..]
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
	assert!(xml.contains("<feedback>"), "{xml}");
	assert!(xml.contains("1.2.3.4"), "{xml}");
}
