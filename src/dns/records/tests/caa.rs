//! Tests for the CAA records.

use super::base::{find, full_config};
use super::*;

#[test]
fn caa_emitted_for_known_lets_encrypt_directory() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		Some("https://acme-v02.api.letsencrypt.org/directory"),
		None,
		None,
	);
	let caa = find(&records, "example.org", RecordKind::Caa);
	assert_eq!(caa.record.value, "0 issue \"letsencrypt.org\"");
}

#[test]
fn caa_emitted_for_known_zerossl_directory() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		Some("https://acme.zerossl.com/v2/DV90"),
		None,
		None,
	);
	let caa = find(&records, "example.org", RecordKind::Caa);
	assert_eq!(caa.record.value, "0 issue \"zerossl.com\"");
}

#[test]
fn caa_omitted_for_unknown_acme_directory() {
	// An unrecognised directory must not emit a CAA — a wrong value would
	// block legitimate renewal, so the safe default is silence.
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		Some("https://acme.example.com/directory"),
		None,
		None,
	);
	assert!(!records.iter().any(|r| r.record.kind == RecordKind::Caa));
}

#[test]
fn caa_directory_with_trailing_slash_is_accepted() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		Some("https://acme-v02.api.letsencrypt.org/directory/"),
		None,
		None,
	);
	let caa = find(&records, "example.org", RecordKind::Caa);
	assert_eq!(caa.record.value, "0 issue \"letsencrypt.org\"");
}

#[test]
fn caa_is_none_when_acme_is_not_configured() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
		None,
	);
	assert!(!records.iter().any(|r| r.record.kind == RecordKind::Caa));
}

#[test]
fn caa_emitted_for_the_google_trust_services_directory() {
	// The hostname here was wrong on the first pass (`gcp-host.com`, which
	// does not resolve), so an operator on Google Trust Services silently got
	// no CAA at all. Checked against the live directory: it answers 200.
	assert_eq!(
		caa_ca_for_directory("https://dv.acme-v02.api.pki.goog/directory"),
		Some("pki.goog"),
	);
}

#[test]
fn caa_is_withheld_for_a_directory_we_do_not_recognise() {
	// Withholding is the safe direction: a CAA naming the wrong CA blocks
	// renewal outright, while a missing CAA just leaves issuance unrestricted.
	assert_eq!(
		caa_ca_for_directory("https://acme.example.test/directory"),
		None,
	);
}
