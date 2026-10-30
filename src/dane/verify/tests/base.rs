//! Tests for applying a DANE policy to a presented certificate chain.

use super::*;
use crate::dane::policy::DaneOutcome;
use crate::dane::tlsa::TlsaRecord;
use ring::digest;

/// A fresh self-signed certificate, returned as DER, with its SPKI DER.
fn self_signed(name: &str) -> (Vec<u8>, Vec<u8>) {
	let certified =
		rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("generate certificate");
	let der = certified.cert.der().to_vec();
	let spki = spki_of(&der).expect("spki parses");
	(der, spki)
}

fn sha256(data: &[u8]) -> Vec<u8> {
	digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

#[test]
fn no_records_is_opportunistic() {
	let (der, _) = self_signed("mx.example.org");
	assert_eq!(verify_chain(&[], &[der]), DaneOutcome::NoRecords);
}

#[test]
fn dane_ee_spki_match_authenticates() {
	let (der, spki) = self_signed("mx.example.org");
	// 3 1 1: DANE-EE, SPKI selector, SHA-256.
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(&spki)).expect("record");
	assert_eq!(verify_chain(&[record], &[der]), DaneOutcome::Authenticated);
}

#[test]
fn dane_ee_full_cert_match_authenticates() {
	let (der, _) = self_signed("mx.example.org");
	// 3 0 1: DANE-EE, full-certificate selector, SHA-256.
	let record = TlsaRecord::from_parts(3, 0, 1, sha256(&der)).expect("record");
	assert_eq!(verify_chain(&[record], &[der]), DaneOutcome::Authenticated);
}

#[test]
fn wrong_association_is_mismatch() {
	let (der, _) = self_signed("mx.example.org");
	// A record for a different key: present but never matches -> fail closed.
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"some other key")).expect("record");
	assert_eq!(verify_chain(&[record], &[der]), DaneOutcome::Mismatch);
}

#[test]
fn records_present_but_empty_chain_is_mismatch() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"key")).expect("record");
	assert_eq!(verify_chain(&[record], &[]), DaneOutcome::Mismatch);
}

#[test]
fn records_present_but_unparseable_chain_is_mismatch() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"key")).expect("record");
	assert_eq!(
		verify_chain(&[record], &[b"not a certificate".to_vec()]),
		DaneOutcome::Mismatch
	);
}

#[test]
fn spki_of_rejects_garbage() {
	assert!(spki_of(b"not a certificate").is_none());
}
