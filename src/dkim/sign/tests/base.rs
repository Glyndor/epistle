use super::*;
use std::collections::HashMap;
use std::io::Write;
use std::pin::Pin;

use crate::spf::{DnsFailure, DnsLookup};

fn temp_signer() -> (Signer, String) {
	let (pem, record) = generate_key().expect("generate");
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(pem.as_bytes()).expect("write key");
	let signer = Signer::load("sel", file.path()).expect("load key");
	// Keep the file alive long enough.
	std::mem::forget(file);
	(signer, record)
}

struct OneKeyDns {
	records: HashMap<String, Vec<String>>,
}

impl DnsLookup for OneKeyDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = Ok(self.records.get(name).cloned().unwrap_or_default());
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn signed_message_verifies_with_own_verifier() {
	let (signer, record) = temp_signer();
	let raw =
		b"From: alice@example.org\r\nSubject: hi\r\nTo: bob@elsewhere.example\r\n\r\nHello\r\n";
	let header = signer.sign("example.org", raw).expect("signs");
	let mut signed = header.into_bytes();
	signed.extend_from_slice(raw);

	let mut records = HashMap::new();
	records.insert("sel._domainkey.example.org".to_string(), vec![record]);
	let dns = OneKeyDns { records };

	let results = crate::dkim::verify_message(&dns, &signed).await;
	assert_eq!(results.len(), 1);
	assert_eq!(
		results[0].outcome,
		crate::dkim::DkimOutcome::Pass,
		"{results:?}"
	);
	assert_eq!(results[0].domain.as_deref(), Some("example.org"));
}

#[test]
fn refuses_to_sign_without_from() {
	let (signer, _) = temp_signer();
	assert!(
		signer
			.sign("example.org", b"Subject: x\r\n\r\nbody\r\n")
			.is_none()
	);
}

#[test]
fn dns_record_value_matches_generated_record() {
	let (signer, record) = temp_signer();
	assert_eq!(signer.dns_record_value(), record);
}

#[test]
fn load_rejects_garbage() {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(b"not a key").expect("write");
	assert!(Signer::load("sel", file.path()).is_err());
	assert!(Signer::load("sel", std::path::Path::new("/nonexistent")).is_err());
}

/// A 2048-bit RSA private key (PKCS#8 PEM) for the dual-signing test only.
const RSA_TEST_KEY: &str = include_str!("../../test_rsa_key.pem");

#[test]
fn dual_signs_with_ed25519_and_rsa() {
	let (signer, _) = temp_signer();
	let mut rsa_file = tempfile::NamedTempFile::new().expect("temp file");
	rsa_file.write_all(RSA_TEST_KEY.as_bytes()).expect("write");
	let signer = signer.with_rsa("rsa", rsa_file.path()).expect("rsa key");

	let message = b"From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n";
	let signed = signer.sign("example.org", message).expect("sign");
	// Two DKIM-Signature headers, one per algorithm.
	assert_eq!(signed.matches("DKIM-Signature:").count(), 2, "{signed}");
	assert!(signed.contains("a=ed25519-sha256"), "{signed}");
	assert!(signed.contains("a=rsa-sha256"), "{signed}");
	assert!(signed.contains("s=sel;"), "{signed}");
	assert!(signed.contains("s=rsa;"), "{signed}");
}

#[test]
fn signs_folded_header_and_empty_body() {
	let (signer, _) = temp_signer();
	// A folded From header and no trailing blank line / body.
	let message = b"From: Alice\r\n <alice@example.org>\r\nSubject: hi\r\n";
	let header = signer.sign("example.org", message).expect("signs");
	assert!(header.starts_with("DKIM-Signature:"), "{header}");
}

#[test]
fn sign_rejects_non_utf8_headers() {
	let (signer, _) = temp_signer();
	assert!(
		signer
			.sign("example.org", b"From: \xff\xfe\r\n\r\nbody\r\n")
			.is_none()
	);
}

#[test]
fn with_rsa_rejects_invalid_key() {
	let (signer, _) = temp_signer();
	let mut bad = tempfile::NamedTempFile::new().expect("temp file");
	bad.write_all(b"-----BEGIN PRIVATE KEY-----\nnotbase64!!!\n-----END PRIVATE KEY-----\n")
		.expect("write");
	assert!(signer.with_rsa("rsa", bad.path()).is_err());
	// A missing file fails too.
	let (signer, _) = temp_signer();
	assert!(
		signer
			.with_rsa("rsa", std::path::Path::new("/nonexistent"))
			.is_err()
	);
}

#[tokio::test]
async fn resolver_stub_methods_are_inert() {
	let dns = OneKeyDns {
		records: HashMap::new(),
	};
	assert!(dns.addresses("x").await.expect("ok").is_empty());
	assert!(dns.mx("x").await.expect("ok").is_empty());
}
