use super::*;

const JSON: &str = r#"{"organization-name":"invented","date-range":{"start-datetime":"0","end-datetime":"1"},"report-id":"r","policies":[]}"#;

#[test]
fn unsigned_tls_report_is_dropped_without_persistence() {
	let message = AcceptedMessage {
		reverse_path: "sender@reporter.example".into(),
		recipients: vec!["tlsrpt@example.org".into()],
		data: format!("From: sender@reporter.example\r\nAuthentication-Results: mail.example.org; spf=pass; dkim=pass header.d=reporter.example\r\nContent-Type: application/tlsrpt+json\r\n\r\n{JSON}").into_bytes(),
		..AcceptedMessage::default()
	};
	let directory = tempfile::tempdir().expect("temporary report directory");
	let metrics = Metrics::new();
	ingest(directory.path(), Kind::TlsRpt, &message, Some(&metrics));
	let snapshot = metrics.snapshot();
	let observed = (
		snapshot.get("reports_dropped").copied().unwrap_or(0),
		snapshot
			.get("tlsrpt_reports_ingested")
			.copied()
			.unwrap_or(0),
		directory.path().join("reports").exists(),
	);
	assert_eq!(
		observed,
		(1, 0, false),
		"unsigned TLS-RPT must be dropped once, never counted or persisted"
	);
}

use crate::dkim::DkimOutcome;
use crate::spf::{DnsFailure, DnsLookup};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::pin::Pin;

struct KeyDns(String);

impl DnsLookup for KeyDns {
	fn txt(
		&self,
		_: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(vec![self.0.clone()]) })
	}

	fn addresses(
		&self,
		_: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn signed_report(domain: &str, length_tag: bool) -> (AcceptedMessage, KeyDns) {
	use crate::dkim::{Canon, canon};
	let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
		.expect("generate signing key");
	let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).expect("load signing key");
	let base64 = base64::engine::general_purpose::STANDARD;
	let body = format!("{JSON}\r\n");
	let canonical_body = canon::body(Canon::Relaxed, body.as_bytes());
	let body_hash = base64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));
	let length = if length_tag {
		format!("l={}; ", canonical_body.len())
	} else {
		String::new()
	};
	let value = format!(
		" v=1; a=ed25519-sha256; d={domain}; s=sel; c=relaxed/relaxed; h=from:content-type; {length}bh={body_hash}; b="
	);
	let from = " sender@reporter.example";
	let content_type = " application/tlsrpt+json";
	let mut header_input = canon::header(Canon::Relaxed, "From", from);
	header_input.push_str(&canon::header(Canon::Relaxed, "Content-Type", content_type));
	let mut signature_line = canon::header(Canon::Relaxed, "DKIM-Signature", &value);
	signature_line.truncate(signature_line.len() - 2);
	header_input.push_str(&signature_line);
	let signature = base64.encode(key.sign(header_input.as_bytes()).as_ref());
	let data = format!(
		"From:{from}\r\nContent-Type:{content_type}\r\nDKIM-Signature:{value}{signature}\r\n\r\n{body}"
	)
	.into_bytes();
	let message = AcceptedMessage {
		reverse_path: "sender@reporter.example".into(),
		recipients: vec!["tlsrpt@example.org".into()],
		data,
		..AcceptedMessage::default()
	};
	let dns = KeyDns(format!(
		"v=DKIM1; k=ed25519; p={}",
		base64.encode(key.public_key().as_ref())
	));
	(message, dns)
}

async fn authenticate_and_ingest(mut message: AcceptedMessage, dns: &KeyDns) -> (u64, u64, bool) {
	message.tlsrpt_verified = crate::dkim::verify_tlsrpt(dns, &message.data).await;
	let directory = tempfile::tempdir().expect("temporary report directory");
	let metrics = Metrics::new();
	ingest(directory.path(), Kind::TlsRpt, &message, Some(&metrics));
	let snapshot = metrics.snapshot();
	(
		snapshot.get("reports_dropped").copied().unwrap_or(0),
		snapshot
			.get("tlsrpt_reports_ingested")
			.copied()
			.unwrap_or(0),
		directory.path().join("reports/tlsrpt").exists(),
	)
}

#[tokio::test]
async fn verified_full_body_report_is_ingested() {
	let (message, dns) = signed_report("reporter.example", false);
	assert_eq!(
		authenticate_and_ingest(message, &dns).await,
		(0, 1, true),
		"verified full-body TLS-RPT must be counted and persisted once"
	);
}

#[tokio::test]
async fn valid_dkim_length_tag_report_is_dropped() {
	let (message, dns) = signed_report("reporter.example", true);
	let results = crate::dkim::verify_message(&dns, &message.data).await;
	assert_eq!(
		results[0].outcome,
		DkimOutcome::Pass,
		"full-length l= fixture must pass ordinary DKIM verification"
	);
	assert_eq!(
		authenticate_and_ingest(message, &dns).await,
		(1, 0, false),
		"TLS-RPT with l= must be dropped even when ordinary DKIM passes"
	);
}

#[tokio::test]
async fn valid_dkim_from_another_domain_is_dropped() {
	let (message, dns) = signed_report("other.example", false);
	let results = crate::dkim::verify_message(&dns, &message.data).await;
	assert_eq!(
		results[0].outcome,
		DkimOutcome::Pass,
		"unaligned fixture must pass ordinary DKIM verification"
	);
	assert_eq!(
		authenticate_and_ingest(message, &dns).await,
		(1, 0, false),
		"TLS-RPT signed by another domain must be dropped without persistence"
	);
}

#[tokio::test]
async fn altered_signed_report_is_dropped() {
	let (mut message, dns) = signed_report("reporter.example", false);
	message.data.extend_from_slice(b"altered\r\n");
	assert_eq!(
		authenticate_and_ingest(message, &dns).await,
		(1, 0, false),
		"TLS-RPT with a failed body signature must be dropped without persistence"
	);
}

#[tokio::test]
async fn invalid_signature_before_valid_signature_does_not_block_ingest() {
	let (mut message, dns) = signed_report("reporter.example", false);
	let mut data = b"DKIM-Signature: invalid\r\n".to_vec();
	data.extend_from_slice(&message.data);
	message.data = data;
	assert_eq!(
		authenticate_and_ingest(message, &dns).await,
		(0, 1, true),
		"a valid reporting-domain signature must authorize ingest after an invalid signature"
	);
}
