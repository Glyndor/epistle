//! Tests for the report-ingest hook into `LocalDelivery`.

use super::*;
use base64::Engine;
use crate::directory_store::DirectoryHandle;
use crate::reports::Kind;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MessageSink;
use crate::storage::LocalDelivery;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("postmaster@example.org".to_string(), "postmaster".to_string()),
			("tlsrpt@example.org".to_string(), "tlsrpt".to_string()),
		],
	))
}

fn message(recipients: &[&str], data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

/// Build a minimal valid DMARC aggregate gzip report whose body, once
/// decompressed and parsed, yields one record from a single org.
fn dmarc_report_bytes() -> Vec<u8> {
	use flate2::write::GzEncoder;
	use std::io::Write;
	let xml = br#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>rid</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <p>reject</p>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
  </record>
</feedback>
"#;
	let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
	enc.write_all(xml).expect("write");
	enc.finish().expect("finish")
}

fn build_message(boundary: &str, parts: &[(String, String, String)]) -> Vec<u8> {
	let mut out = String::new();
	out.push_str("MIME-Version: 1.0\r\n");
	out.push_str(&format!(
		"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
	));
	out.push_str("\r\n");
	for (ct, cte, body) in parts {
		out.push_str(&format!("--{boundary}\r\n"));
		out.push_str(&format!("Content-Type: {ct}\r\n"));
		out.push_str(&format!("Content-Transfer-Encoding: {cte}\r\n"));
		out.push_str("\r\n");
		out.push_str(body);
		out.push_str("\r\n");
	}
	out.push_str(&format!("--{boundary}--\r\n"));
	out.into_bytes()
}

fn b64(bytes: &[u8]) -> String {
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A report addressed to `postmaster@<domain>` is ingested and still lands
/// in the named account's mailbox.
#[test]
fn a_report_to_postmaster_is_ingested_and_still_delivered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
	let delivery = LocalDelivery::new(dir.path(), directory())
		.expect("delivery")
		.with_metrics(metrics.clone());
	let payload = build_message(
		"BOUND",
		&[(
			"application/gzip".into(),
			"base64".into(),
			b64(&dmarc_report_bytes()),
		)],
	);
	delivery
		.deliver(message(&["postmaster@example.org"], &payload))
		.expect("deliver");
	// Mailbox still has the report copy (the operator can read raw).
	let new_dir = dir.path().join("accounts").join("postmaster").join("new");
	assert_eq!(
		std::fs::read_dir(&new_dir).map(|e| e.count()).unwrap_or(0),
		1
	);
	// JSONL report lands under reports/dmarc/{YYYYMMDD}/.
	let reports_root = dir.path().join("reports").join("dmarc");
	let mut found = false;
	for entry in std::fs::read_dir(&reports_root)
		.expect("reports root")
		.flatten()
	{
		let day_dir = entry.path();
		if day_dir.is_dir() {
			let jsonl = day_dir.join("google.com.jsonl");
			if jsonl.exists() {
				found = true;
				break;
			}
		}
	}
	assert!(found, "no DMARC JSONL persisted under {reports_root:?}");
	// Counter bumped once.
	let snap = metrics.snapshot();
	assert_eq!(snap.get("dmarc_reports_ingested"), Some(&1));
}

/// A recipient that is neither `postmaster@` nor `tlsrpt@` is untouched.
#[test]
fn a_report_to_an_ordinary_account_is_not_ingested() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
	let delivery = LocalDelivery::new(dir.path(), directory())
		.expect("delivery")
		.with_metrics(metrics.clone());
	let payload = build_message(
		"BOUND",
		&[(
			"application/gzip".into(),
			"base64".into(),
			b64(&dmarc_report_bytes()),
		)],
	);
	delivery
		.deliver(message(&["alice@example.org"], &payload))
		.expect("deliver");
	let reports_root = dir.path().join("reports").join("dmarc");
	assert!(!reports_root.exists(), "reports root must not appear");
	let snap = metrics.snapshot();
	assert_eq!(snap.get("dmarc_reports_ingested").copied().unwrap_or(0), 0);
}

/// An oversized report is dropped, the mailbox copy still lands, and
/// `reports_dropped` is bumped.
#[test]
fn an_oversized_report_is_dropped_and_counted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
	let delivery = LocalDelivery::new(dir.path(), directory())
		.expect("delivery")
		.with_metrics(metrics.clone());
	// 25 MiB of zeros; compressed this fits in well under MAX_COMPRESSED,
	// so the bomb trips on the way out, the way `decompress` is designed.
	let big = vec![0u8; 25 * 1024 * 1024];
	let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	use std::io::Write;
	enc.write_all(&big).expect("write");
	let gz = enc.finish().expect("finish");
	assert!(gz.len() < 64 * 1024, "{}", gz.len());
	let payload = build_message(
		"BOUND",
		&[("application/gzip".into(), "base64".into(), b64(&gz))],
	);
	delivery
		.deliver(message(&["postmaster@example.org"], &payload))
		.expect("deliver");
	let new_dir = dir.path().join("accounts").join("postmaster").join("new");
	assert_eq!(
		std::fs::read_dir(&new_dir).map(|e| e.count()).unwrap_or(0),
		1,
		"mailbox still receives the oversized report"
	);
	let snap = metrics.snapshot();
	assert_eq!(snap.get("reports_dropped"), Some(&1));
}

/// `report_kind` only fires for `postmaster@` or `tlsrpt@` against a
/// domain the directory serves. Other locals and unserved domains are no-ops.
#[test]
fn report_kind_matches_only_postmaster_and_tlsrpt() {
	let domains = vec!["example.org".to_string()];
	assert_eq!(
		report_kind("postmaster", "example.org", &domains),
		Some(Kind::Dmarc)
	);
	assert_eq!(
		report_kind("tlsrpt", "example.org", &domains),
		Some(Kind::TlsRpt)
	);
	assert_eq!(report_kind("alice", "example.org", &domains), None);
	assert_eq!(report_kind("postmaster", "other.example", &domains), None);
	assert_eq!(report_kind("postmaster", "example.com", &domains), None);
}

#[test]
fn tlsrpt_address_ingests_a_tlsrpt_report() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
	let delivery = LocalDelivery::new(dir.path(), directory())
		.expect("delivery")
		.with_metrics(metrics.clone());
	let json = br#"{"organization-name":"google.com","date-range":{"start-datetime":"2024-01-01T00:00:00Z","end-datetime":"2024-01-02T00:00:00Z"},"report-id":"rid","policies":[]}"#;
	let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	use std::io::Write;
	enc.write_all(json).expect("write");
	let gz = enc.finish().expect("finish");
	let payload = build_message(
		"BOUND",
		&[(
			"application/tlsrpt+gzip".into(),
			"base64".into(),
			b64(&gz),
		)],
	);
	delivery
		.deliver(message(&["tlsrpt@example.org"], &payload))
		.expect("deliver");
	let snap = metrics.snapshot();
	assert_eq!(snap.get("tlsrpt_reports_ingested"), Some(&1));
}