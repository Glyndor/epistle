//! RSA verification against the key records senders really publish.
//!
//! RFC 6376 §3.6.1 publishes an RSA key as the base64 of a
//! SubjectPublicKeyInfo (what `openssl rsa -pubout` prints and what large
//! senders publish); some older records carry the bare PKCS#1
//! `RSAPublicKey`. Both must verify.

use std::collections::HashMap;
use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::*;
use crate::dkim::Signer;
use crate::dkim::test_support::KeyDns;

const RSA_TEST_KEY: &str = include_str!("test_rsa_key.pem");
const MESSAGE: &[u8] = b"From: a@example.org\r\nTo: b@example.net\r\nSubject: hi\r\n\r\nbody\r\n";

/// A message dual-signed for example.org, and the RSA `p=` value in SPKI form.
fn dual_signed() -> (Vec<u8>, String, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let ed = dir.path().join("ed.pem");
	let (pem, _) = crate::dkim::generate_key().expect("ed25519 key");
	std::fs::write(&ed, pem).expect("write ed25519 key");
	let mut rsa = tempfile::NamedTempFile::new().expect("temp file");
	rsa.write_all(RSA_TEST_KEY.as_bytes())
		.expect("write RSA key");
	let signer = Signer::load("ed", &ed)
		.expect("ed25519 signer")
		.with_rsa("rsa", rsa.path())
		.expect("RSA signer");
	let ed_record = signer.dns_record_value();
	let rsa_record = signer.rsa_dns_record_value().expect("RSA record");
	let header = signer.sign("example.org", MESSAGE).expect("sign");
	let mut message = header.into_bytes();
	message.extend_from_slice(MESSAGE);
	(message, ed_record, rsa_record)
}

fn dns(ed_record: &str, rsa_record: &str) -> KeyDns {
	KeyDns(HashMap::from([
		(
			"ed._domainkey.example.org".to_string(),
			vec![ed_record.to_string()],
		),
		(
			"rsa._domainkey.example.org".to_string(),
			vec![rsa_record.to_string()],
		),
	]))
}

fn outcomes(results: &[DkimResult]) -> Vec<DkimOutcome> {
	results.iter().map(|result| result.outcome).collect()
}

#[tokio::test]
async fn an_rsa_signature_verifies_against_a_subject_public_key_info_record() {
	let (message, ed_record, rsa_record) = dual_signed();
	let results = verify_message(&dns(&ed_record, &rsa_record), &message).await;
	assert_eq!(outcomes(&results), [DkimOutcome::Pass, DkimOutcome::Pass]);
}

#[tokio::test]
async fn an_rsa_signature_verifies_against_a_bare_rsa_public_key_record() {
	let (message, ed_record, rsa_record) = dual_signed();
	let spki = BASE64
		.decode(rsa_record.rsplit("p=").next().expect("p= tag"))
		.expect("base64 key");
	let pkcs1 = crate::dkim::spki::rsa_public_key_from_spki(&spki).expect("an RSA SPKI");
	let bare = format!("v=DKIM1; k=rsa; p={}", BASE64.encode(pkcs1));
	let results = verify_message(&dns(&ed_record, &bare), &message).await;
	assert_eq!(outcomes(&results), [DkimOutcome::Pass, DkimOutcome::Pass]);
}

#[tokio::test]
async fn an_rsa_signature_fails_against_another_key() {
	let (message, ed_record, _) = dual_signed();
	let other_record = another_rsa_record();
	let results = verify_message(&dns(&ed_record, &other_record), &message).await;
	assert_eq!(outcomes(&results), [DkimOutcome::Pass, DkimOutcome::Fail]);
}

#[tokio::test]
async fn a_tampered_body_fails_the_rsa_signature_too() {
	let (mut message, ed_record, rsa_record) = dual_signed();
	let last = message.len() - 3;
	message[last] ^= 0x01;
	let results = verify_message(&dns(&ed_record, &rsa_record), &message).await;
	assert_eq!(outcomes(&results), [DkimOutcome::Fail, DkimOutcome::Fail]);
}

/// An RSA key record for a key other than the test key, generated with
/// openssl at test time.
fn another_rsa_record() -> String {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = dir.path().join("other.pem");
	let status = std::process::Command::new("openssl")
		.args([
			"genpkey",
			"-algorithm",
			"RSA",
			"-pkeyopt",
			"rsa_keygen_bits:2048",
			"-out",
		])
		.arg(&key)
		.stderr(std::process::Stdio::null())
		.status()
		.expect("openssl runs");
	assert!(status.success(), "openssl generates a key");
	let ed = dir.path().join("ed.pem");
	let (pem, _) = crate::dkim::generate_key().expect("ed25519 key");
	std::fs::write(&ed, pem).expect("write ed25519 key");
	let signer = Signer::load("ed", &ed)
		.expect("ed25519 signer")
		.with_rsa("rsa", &key)
		.expect("RSA signer");
	signer.rsa_dns_record_value().expect("RSA record")
}
