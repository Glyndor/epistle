//! Compare production signatures to an independent Python cryptography oracle.

use super::harness::*;
use epistle::dkim::Signer;

fn signer() -> Signer {
	Signer::load("external", &path("ed25519-ring.pem")).expect("fixed Ed25519 PKCS8 v2")
}

fn fields(raw: &str) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for line in raw.split_inclusive("\r\n") {
		if line.starts_with("DKIM-Signature:") {
			out.push(String::new());
		}
		out.last_mut().expect("signature field").push_str(line);
	}
	out
}

fn matches_oracle(field: &str, key: &str) {
	let value = field
		.strip_prefix("DKIM-Signature:")
		.expect("signature header");
	let (unsigned, encoded) = value.split_once("b=").expect("b tag");
	assert_eq!(
		format!("{unsigned}b="),
		text(&format!("signer-{key}.unsigned"))
	);
	let encoded: String = encoded
		.chars()
		.filter(|c| !c.is_ascii_whitespace())
		.collect();
	assert_eq!(encoded, text(&format!("signer-{key}.signature")).trim());
}

#[test]
fn ed25519_signer_matches_external_signature_and_wire_input() {
	bounded(|| {
		let signature = signer()
			.sign("example.test", &bytes("signer-raw.eml"))
			.expect("signs");
		let signatures = fields(&signature);
		assert_eq!(signatures.len(), 1);
		matches_oracle(&signatures[0], "ed25519");
	});
}

#[test]
fn dual_signer_matches_both_external_signatures() {
	bounded(|| {
		let signer = signer()
			.with_rsa("external", &path("rsa2048.pem"))
			.expect("RSA key");
		let signature = signer
			.sign("example.test", &bytes("signer-raw.eml"))
			.expect("signs");
		let signatures = fields(&signature);
		assert_eq!(signatures.len(), 2);
		matches_oracle(&signatures[0], "ed25519");
		matches_oracle(&signatures[1], "rsa2048");
	});
}

#[test]
fn signer_refuses_duplicate_from() {
	bounded(|| {
		let mut raw = b"From: attacker@evil.test\r\n".to_vec();
		raw.extend_from_slice(&bytes("signer-raw.eml"));
		assert_eq!(signer().sign("example.test", &raw), None);
	});
}

#[test]
fn signer_refuses_missing_from() {
	bounded(|| {
		assert_eq!(
			signer().sign("example.test", b"Subject: absent From\r\n\r\nbody\r\n"),
			None
		)
	});
}
