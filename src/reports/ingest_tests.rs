use super::*;
use base64::Engine;

const EMPTY_TLS: &str = r#"{"organization-name":"org","date-range":{"start-datetime":"0","end-datetime":"1"},"report-id":"r","policies":[]}"#;

#[test]
fn truncated_zip_mime_is_counted_as_dropped() {
	let mut zip = vec![0; 30];
	zip[..4].copy_from_slice(b"PK\x03\x04");
	zip[6] = 8;
	zip.extend_from_slice(b"PK\x05\x06");
	let body = base64::engine::general_purpose::STANDARD.encode(zip);
	let data =
		format!("Content-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\n\r\n{body}")
			.into_bytes();
	let message = AcceptedMessage {
		reverse_path: "sender@example.org".into(),
		recipients: vec!["postmaster@example.org".into()],
		data,
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	};
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Metrics::new();
	ingest(dir.path(), Kind::Dmarc, &message, Some(&metrics));
	assert_eq!(metrics.snapshot().get("reports_dropped"), Some(&1));
	assert!(!dir.path().join("reports").exists());
}

#[test]
fn uncompressed_tls_json_content_type_reaches_parser() {
	let raw = format!("Content-Type: application/tlsrpt+json\r\n\r\n{EMPTY_TLS}");
	let Parsed::TlsRpt(report) = ingest_inner(Kind::TlsRpt, raw.as_bytes()).expect("plain JSON")
	else {
		panic!("wrong report kind");
	};
	assert_eq!(report.report_id, "r");
}

#[test]
fn uncompressed_tls_json_filename_reaches_parser() {
	let raw = format!(
		"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=report.json\r\n\r\n{EMPTY_TLS}"
	);
	let Parsed::TlsRpt(report) =
		ingest_inner(Kind::TlsRpt, raw.as_bytes()).expect("plain JSON filename")
	else {
		panic!("wrong report kind");
	};
	assert_eq!(report.report_id, "r");
}
