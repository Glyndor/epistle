//! Tests for expected-record computation and the TLSA association builder.

use super::*;

fn find<'a>(records: &'a [PublishRecord], name: &str, kind: RecordKind) -> &'a PublishRecord {
	records
		.iter()
		.find(|r| r.record.name == name && r.record.kind == kind)
		.unwrap_or_else(|| panic!("no {kind:?} record for {name}"))
}

#[test]
fn builds_core_records_per_domain() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		Some(("mail", "v=DKIM1; k=ed25519; p=AAAA")),
		None,
		"v1",
	);

	assert_eq!(
		find(&records, "example.org", RecordKind::Txt).record.value,
		"v=spf1 mx ~all"
	);
	assert!(
		find(&records, "_dmarc.example.org", RecordKind::Txt)
			.record
			.value
			.starts_with("v=DMARC1;")
	);
	assert_eq!(
		find(&records, "_mta-sts.example.org", RecordKind::Txt)
			.record
			.value,
		"v=STSv1; id=v1"
	);
	assert_eq!(
		find(&records, "example.org", RecordKind::Mx).record.value,
		"10 mail.example.org"
	);
	assert_eq!(
		find(&records, "mail._domainkey.example.org", RecordKind::Txt)
			.record
			.value,
		"v=DKIM1; k=ed25519; p=AAAA"
	);
}

#[test]
fn omits_dkim_when_absent_and_tlsa_when_no_cert() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		None,
		None,
		"v1",
	);
	assert!(!records.iter().any(|r| r.record.name.contains("_domainkey")));
	assert!(!records.iter().any(|r| r.record.kind == RecordKind::Tlsa));
}

#[test]
fn tlsa_record_added_once_for_host() {
	let records = build_records(
		&["a.example".to_string(), "b.example".to_string()],
		"mail.host.example",
		None,
		Some("3 0 1 abcd"),
		"v1",
	);
	let tlsa: Vec<_> = records
		.iter()
		.filter(|r| r.record.kind == RecordKind::Tlsa)
		.collect();
	assert_eq!(tlsa.len(), 1);
	assert_eq!(tlsa[0].record.name, "_25._tcp.mail.host.example");
	assert_eq!(tlsa[0].record.value, "3 0 1 abcd");
}

#[test]
fn tlsa_full_cert_hashes_the_leaf() {
	let cert = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
		.expect("self-signed");
	let pem = cert.cert.pem();
	let assoc = tlsa_full_cert(&pem).expect("association");
	// DANE-EE, full cert, SHA-256: "3 0 1 " + 64 hex chars.
	assert!(assoc.starts_with("3 0 1 "), "{assoc}");
	let hex = assoc.strip_prefix("3 0 1 ").unwrap();
	assert_eq!(hex.len(), 64, "{assoc}");
	assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{assoc}");
}

#[test]
fn tlsa_full_cert_rejects_non_pem() {
	assert_eq!(tlsa_full_cert("not a certificate"), None);
	assert_eq!(
		tlsa_full_cert("-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n"),
		None
	);
}
