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
		&[("mail".to_string(), "v=DKIM1; k=ed25519; p=AAAA".to_string())],
		None,
		"v1",
		Services::all(),
		None,
	);

	assert_eq!(
		find(&records, "example.org", RecordKind::Txt).record.value,
		"v=spf1 mx -all"
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
		find(&records, "_smtp._tls.example.org", RecordKind::Txt)
			.record
			.value,
		"v=TLSRPTv1; rua=mailto:tlsrpt@example.org"
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
		&[],
		None,
		"v1",
		Services::all(),
		None,
	);
	assert!(!records.iter().any(|r| r.record.name.contains("_domainkey")));
	assert!(!records.iter().any(|r| r.record.kind == RecordKind::Tlsa));
}

#[test]
fn tlsa_record_added_once_for_host() {
	let records = build_records(
		&["a.example".to_string(), "b.example".to_string()],
		"mail.host.example",
		&[],
		Some("3 0 1 abcd"),
		"v1",
		Services::all(),
		None,
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
fn builds_srv_records_for_mail_jmap_and_sieve() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::all(),
		None,
	);
	let submissions = find(&records, "_submissions._tcp.example.org", RecordKind::Srv);
	assert_eq!(submissions.record.value, "0 1 465 mail.example.org.");
	let jmap = find(&records, "_jmap._tcp.example.org", RecordKind::Srv);
	assert_eq!(jmap.record.value, "0 1 443 mail.example.org.");
	let sieve = find(&records, "_sieve._tcp.example.org", RecordKind::Srv);
	assert_eq!(sieve.record.value, "0 1 4190 mail.example.org.");
}

#[test]
fn builds_discovery_cnames_for_autoconfig_autodiscover_and_mta_sts() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::all(),
		None,
	);
	let autoconfig = find(&records, "autoconfig.example.org", RecordKind::Cname);
	assert_eq!(autoconfig.record.value, "mail.example.org");
	let autodiscover = find(&records, "autodiscover.example.org", RecordKind::Cname);
	assert_eq!(autodiscover.record.value, "mail.example.org");
	let mta_sts = find(&records, "mta-sts.example.org", RecordKind::Cname);
	assert_eq!(mta_sts.record.value, "mail.example.org");
}

#[test]
fn caldav_and_carddav_srv_are_optional() {
	let without = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::default(),
		None,
	);
	assert!(
		!without
			.iter()
			.any(|r| r.record.name == "_caldavs._tcp.example.org")
	);
	assert!(
		!without
			.iter()
			.any(|r| r.record.name == "_carddavs._tcp.example.org")
	);
	let with = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::all(),
		None,
	);
	assert!(
		with.iter()
			.any(|r| r.record.name == "_caldavs._tcp.example.org"
				&& r.record.value == "0 1 443 mail.example.org.")
	);
	assert!(
		with.iter()
			.any(|r| r.record.name == "_carddavs._tcp.example.org"
				&& r.record.value == "0 1 443 mail.example.org.")
	);
}

#[test]
fn caa_emitted_for_known_lets_encrypt_directory() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::all(),
		Some("https://acme-v02.api.letsencrypt.org/directory"),
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
		None,
		"v1",
		Services::all(),
		Some("https://acme.zerossl.com/v2/DV90"),
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
		None,
		"v1",
		Services::all(),
		Some("https://acme.example.com/directory"),
	);
	assert!(!records.iter().any(|r| r.record.kind == RecordKind::Caa));
}

#[test]
fn caa_directory_with_trailing_slash_is_accepted() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::all(),
		Some("https://acme-v02.api.letsencrypt.org/directory/"),
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
		None,
		"v1",
		Services::all(),
		None,
	);
	assert!(!records.iter().any(|r| r.record.kind == RecordKind::Caa));
}

#[test]
fn both_dkim_selectors_are_emitted() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[
			("mail".to_string(), "v=DKIM1; k=ed25519; p=AAAA".to_string()),
			("rsasel".to_string(), "v=DKIM1; k=rsa; p=BBBB".to_string()),
		],
		None,
		"v1",
		Services::all(),
		None,
	);
	assert_eq!(
		find(&records, "mail._domainkey.example.org", RecordKind::Txt)
			.record
			.value,
		"v=DKIM1; k=ed25519; p=AAAA"
	);
	assert_eq!(
		find(&records, "rsasel._domainkey.example.org", RecordKind::Txt)
			.record
			.value,
		"v=DKIM1; k=rsa; p=BBBB"
	);
}

#[test]
fn a_short_value_is_one_string() {
	assert_eq!(
		txt_strings("v=DKIM1; k=ed25519; p=AAAA"),
		vec!["v=DKIM1; k=ed25519; p=AAAA".to_string()]
	);
}

#[test]
fn a_410_byte_value_splits_into_two_strings_on_a_char_boundary() {
	// Build a value with a multi-byte UTF-8 codepoint straddling the 255-byte
	// cut. `ñ` (U+00F1) encodes as 0xC3 0xB1, two bytes. Position it so
	// the codepoint starts at byte 254 (occupying 254..256) and the cut
	// would land mid-codepoint without the boundary guard.
	let mut fragile_value = String::new();
	fragile_value.push_str(&"A".repeat(254));
	fragile_value.push('\u{00F1}'); // bytes 254..256: straddles byte 255
	fragile_value.push_str(&"A".repeat(200));

	let parts = txt_strings(&fragile_value);
	assert!(parts.len() >= 2, "got {} parts", parts.len());
	for part in &parts {
		assert!(
			part.len() <= 255,
			"string of {} bytes is too long",
			part.len()
		);
		assert!(
			std::str::from_utf8(part.as_bytes()).is_ok(),
			"split mid-character"
		);
	}
	// Joining the parts must reproduce the original, resolvers see one
	// logical TXT record again.
	let joined: String = parts.concat();
	assert_eq!(joined, fragile_value);
}

#[test]
fn zone_form_escapes_quotes_and_backslashes() {
	assert_eq!(txt_zone_form(r#"a"b\c"#), r#""a\"b\\c""#.to_string());
}

#[test]
fn zone_form_wraps_long_values_in_multiple_quoted_strings() {
	let value: String = "a".repeat(600);
	let rendered = txt_zone_form(&value);
	assert!(rendered.starts_with('"'));
	assert!(rendered.ends_with('"'));
	// One quote pair per split string, no character split mid-string.
	let quote_count = rendered.chars().filter(|c| *c == '"').count();
	assert_eq!(quote_count, txt_strings(&value).len() * 2);
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

#[tokio::test]
async fn publish_tlsa_upserts_a_3_0_1_record() {
	use crate::dns::provider::{DnsProvider, ProviderError};
	use std::pin::Pin;
	use std::sync::Mutex;

	#[derive(Default)]
	struct Capture(Mutex<Vec<super::PublishRecord>>);
	impl DnsProvider for Capture {
		fn upsert(
			&self,
			zone: &str,
			record: super::DnsRecord,
		) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
			self.0.lock().unwrap().push(super::PublishRecord {
				zone: zone.to_string(),
				record,
			});
			Box::pin(async { Ok(()) })
		}
		fn delete(
			&self,
			_zone: &str,
			_record: super::DnsRecord,
		) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
			Box::pin(async { Ok(()) })
		}
		fn list(
			&self,
			_zone: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<super::DnsRecord>, ProviderError>> + Send + '_>>
		{
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	let cert =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()]).expect("cert");
	let provider = Capture::default();
	publish_tlsa(&provider, "mail.example.org", &cert.cert.pem())
		.await
		.expect("publish");
	let captured = provider.0.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert_eq!(captured[0].record.name, "_25._tcp.mail.example.org");
	assert_eq!(captured[0].record.kind, RecordKind::Tlsa);
	assert!(captured[0].record.value.starts_with("3 0 1 "));
}

#[tokio::test]
async fn publish_tlsa_noop_without_certificate() {
	use crate::dns::provider::ManualProvider;
	// No cert in the PEM → nothing to publish, no error.
	publish_tlsa(&ManualProvider, "mail.example.org", "garbage")
		.await
		.expect("noop");
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
		None
	);
}
