//! Outgoing header coverage and RFC 6376 section 5.4 oversigning.

use std::collections::HashMap;

use super::*;
use crate::dkim::test_support::{KeyDns, signature_headers};
use crate::dkim::{DkimOutcome, verify_message};

pub(super) const FIELDS: &[(&str, &str, bool)] = &[
	("From", "alice@example.org", true),
	("To", "bob@example.net", true),
	("Cc", "carol@example.net", true),
	("Subject", "hello", true),
	("Date", "Sun, 18 Oct 2026 12:00:00 +0000", true),
	("Message-ID", "<message@example.org>", true),
	("Reply-To", "reply@example.org", true),
	("Sender", "sender@example.org", false),
	("MIME-Version", "1.0", false),
	("Content-Type", "text/plain; charset=utf-8", true),
	("Content-Transfer-Encoding", "7bit", false),
	("References", "<parent@example.org>", false),
	("In-Reply-To", "<parent@example.org>", false),
	("List-Id", "news.example.org", false),
	(
		"List-Unsubscribe",
		"<https://example.org/unsubscribe>",
		true,
	),
	("List-Unsubscribe-Post", "List-Unsubscribe=One-Click", true),
	("List-Help", "<https://example.org/help>", false),
	("List-Post", "<mailto:news@example.org>", false),
	("List-Owner", "<mailto:owner@example.org>", false),
	("List-Archive", "<https://example.org/archive>", false),
	("Feedback-ID", "campaign:sender", false),
	("Disposition-Notification-To", "alice@example.org", true),
	("Return-Receipt-To", "alice@example.org", true),
	("Auto-Submitted", "auto-generated", true),
	("Organization", "Example Org", false),
	("X-Epistle", "1", false),
];

pub(super) fn fixture(dual: bool) -> (Signer, KeyDns) {
	let dir = tempfile::tempdir().expect("tempdir");
	let ed_path = dir.path().join("ed.pem");
	let (pem, _) = generate_key().expect("generate key");
	std::fs::write(&ed_path, pem).expect("write key");
	let mut signer = Signer::load("ed", &ed_path).expect("load key");
	let mut records = HashMap::from([(
		"ed._domainkey.example.org".into(),
		vec![signer.dns_record_value()],
	)]);
	if dual {
		let rsa_path = dir.path().join("rsa.pem");
		std::fs::write(&rsa_path, include_str!("../../test_rsa_key.pem")).expect("write RSA key");
		signer = signer.with_rsa("rsa", &rsa_path).expect("load RSA key");
		records.insert(
			"rsa._domainkey.example.org".into(),
			vec![signer.rsa_dns_record_value().expect("RSA record")],
		);
	}
	(signer, KeyDns(records))
}

pub(super) fn message() -> String {
	let mut raw = String::new();
	for (name, value, _) in FIELDS {
		raw.push_str(&format!("{name}: {value}\r\n"));
	}
	raw.push_str("\r\nbody\r\n");
	raw
}

pub(super) fn names(signature: &str) -> Vec<String> {
	super::super::super::signature::parse(
		signature.strip_prefix("DKIM-Signature:").expect("header"),
	)
	.expect("parse signature")
	.signed_headers
}

fn algorithm_selector_domain(signature: &str) -> (String, String, String) {
	let parsed = super::super::super::signature::parse(
		signature.strip_prefix("DKIM-Signature:").expect("header"),
	)
	.expect("parse signature");
	let algorithm = match parsed.algorithm {
		super::super::super::signature::Algorithm::Ed25519Sha256 => "ed25519-sha256",
		super::super::super::signature::Algorithm::RsaSha256 => "rsa-sha256",
	};
	(algorithm.to_string(), parsed.selector, parsed.domain)
}

pub(super) async fn check(dns: &KeyDns, signature: &str, raw: &str, expected: DkimOutcome) {
	let signed = format!("{signature}{raw}");
	let results = verify_message(dns, signed.as_bytes()).await;
	assert_eq!(results.len(), signature_headers(signature.as_bytes()).len());
	for result in results {
		assert_eq!(result.outcome, expected);
	}
}

#[tokio::test]
async fn signs_every_documented_field_with_both_algorithms() {
	for dual in [false, true] {
		let (signer, dns) = fixture(dual);
		let raw = message();
		let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
		let fields = signature_headers(signature.as_bytes());
		assert_eq!(fields.len(), if dual { 2 } else { 1 });
		let expected: Vec<(String, String, String)> = if dual {
			vec![
				(
					"ed25519-sha256".to_string(),
					"ed".to_string(),
					"example.org".to_string(),
				),
				(
					"rsa-sha256".to_string(),
					"rsa".to_string(),
					"example.org".to_string(),
				),
			]
		} else {
			vec![(
				"ed25519-sha256".to_string(),
				"ed".to_string(),
				"example.org".to_string(),
			)]
		};
		let seen: Vec<_> = fields
			.iter()
			.map(|field| algorithm_selector_domain(field))
			.collect();
		assert_eq!(seen, expected);
		let lists: Vec<_> = fields.iter().map(|field| names(field.as_str())).collect();
		for list in &lists {
			for (name, _, oversigned) in FIELDS {
				assert_eq!(
					list.iter()
						.filter(|field| field.eq_ignore_ascii_case(name))
						.count(),
					1 + usize::from(*oversigned),
					"{name}"
				);
			}
			assert_eq!(list.len(), FIELDS.len() + 13);
		}
		assert!(lists.windows(2).all(|pair| pair[0] == pair[1]));
		check(&dns, &signature, &raw, DkimOutcome::Pass).await;
	}
}

#[tokio::test]
async fn an_lf_only_message_signs_and_verifies_its_body() {
	let (signer, dns) = fixture(false);
	let raw = "From: alice@example.org\nSubject: hi\n\nbody\n";
	let signature = signer.sign("example.org", raw.as_bytes()).expect("signs");
	let (_, body) = raw.split_once("\n\n").expect("independent LF boundary");
	assert_eq!(body, "body\n");
	let expected = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, b"body\r\n"));
	assert!(signature.contains(&format!("bh={expected}")), "{signature}");
	for field in signature_headers(signature.as_bytes()) {
		let listed = names(&field);
		assert_eq!(listed.iter().filter(|name| *name == "from").count(), 2);
		assert_eq!(listed.iter().filter(|name| *name == "subject").count(), 2);
	}
	let wire = format!("{signature}{}", raw.replace('\n', "\r\n"));
	let (_, wire_body) = wire
		.split_once("\r\n\r\n")
		.expect("independent CRLF boundary");
	assert_eq!(wire_body, "body\r\n");
	let results = verify_message(&dns, wire.as_bytes()).await;
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].outcome, DkimOutcome::Pass);
}

#[test]
fn a_message_that_starts_with_a_blank_line_has_no_signable_from() {
	let (signer, _) = fixture(false);
	assert!(
		signer
			.sign(
				"example.org",
				b"\r\nFrom: attacker@example.org\r\n\r\nbody\r\n"
			)
			.is_none()
	);
}

#[tokio::test]
async fn changing_or_removing_each_signed_field_invalidates_both_signatures() {
	let (signer, dns) = fixture(true);
	let raw = message();
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	check(&dns, &signature, &raw, DkimOutcome::Pass).await;
	for (name, value, _) in FIELDS {
		let line = format!("{name}: {value}\r\n");
		for replacement in [format!("{name}: changed\r\n"), String::new()] {
			let changed = raw.replacen(&line, &replacement, 1);
			check(&dns, &signature, &changed, DkimOutcome::Fail).await;
		}
	}
}

#[tokio::test]
async fn adding_identical_important_fields_above_or_below_invalidates_signatures() {
	let (signer, dns) = fixture(true);
	let raw = message();
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	for (name, value, oversigned) in FIELDS {
		if !oversigned {
			continue;
		}
		let line = format!("{name}: {value}\r\n");
		for changed in [
			format!("{line}{raw}"),
			raw.replace("\r\n\r\n", &format!("\r\n{line}\r\n")),
		] {
			check(&dns, &signature, &changed, DkimOutcome::Fail).await;
		}
	}
}

mod wire;
