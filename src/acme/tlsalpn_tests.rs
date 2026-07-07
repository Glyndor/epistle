//! Structural tests for the TLS-ALPN-01 challenge certificate and store.

use super::*;
use x509_parser::prelude::FromDer;

#[test]
fn challenge_cert_carries_critical_acme_identifier() {
	let domain = "host.example.org";
	let key_auth = "token.thumbprint";
	let (cert, _key) = challenge_certificate(domain, key_auth).expect("build challenge cert");

	let (_, parsed) =
		x509_parser::certificate::X509Certificate::from_der(cert.as_ref()).expect("parse");
	let ext = parsed
		.extensions()
		.iter()
		.find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
		.expect("acmeIdentifier extension present");
	assert!(ext.critical, "acmeIdentifier must be critical");

	// Value is a DER OCTET STRING wrapping SHA-256(key authorization).
	let digest = ring::digest::digest(&ring::digest::SHA256, key_auth.as_bytes());
	let mut expected = vec![0x04, 0x20];
	expected.extend_from_slice(digest.as_ref());
	assert_eq!(ext.value, expected.as_slice());

	// The certificate names the domain under validation.
	let san = parsed
		.subject_alternative_name()
		.expect("san result")
		.expect("san present");
	let has_domain = san
		.value
		.general_names
		.iter()
		.any(|n| matches!(n, x509_parser::extensions::GeneralName::DNSName(d) if *d == domain));
	assert!(has_domain, "challenge cert must name the domain");
}

#[test]
fn different_key_authorizations_yield_different_digests() {
	let (a, _) = challenge_certificate("h.example", "tok.a").expect("a");
	let (b, _) = challenge_certificate("h.example", "tok.b").expect("b");
	assert_ne!(a.as_ref(), b.as_ref());
}

#[test]
fn store_registers_and_removes_challenge() {
	let store = AlpnChallengeStore::new();
	assert!(store.get("host.example.org").is_none());
	store
		.set("Host.Example.ORG", "token.thumbprint")
		.expect("set");
	// Lookup is case-insensitive.
	assert!(store.get("host.example.org").is_some());
	store.remove("host.example.org");
	assert!(store.get("host.example.org").is_none());
}
