//! Tests for expected-record computation and the TLSA association builder.

use super::*;

use crate::config::Config;

/// A configuration that exposes every service epistle serves, so the
/// records of a full deployment can be computed. The API section is there
/// because the JMAP locator names the API that serves it.
pub(super) fn full_config() -> Config {
	let mut text = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n\
		 [api]\n\
		 token_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'\n",
	);
	for kind in [
		"imap",
		"imaps",
		"submission",
		"submissions",
		"pop3s",
		"manage-sieve",
		"api",
		"web-dav",
		"autoconfig",
	] {
		text.push_str(&format!("\n[[listeners]]\nkind = '{kind}'\n"));
	}
	toml::from_str(&text).expect("config")
}

pub(super) fn find<'a>(
	records: &'a [PublishRecord],
	name: &str,
	kind: RecordKind,
) -> &'a PublishRecord {
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
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
		&DomainDkim::new(),
		Some("3 0 1 abcd"),
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::default(),
		None,
		None,
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
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
fn both_dkim_selectors_are_emitted() {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[
			("mail".to_string(), "v=DKIM1; k=ed25519; p=AAAA".to_string()),
			("rsasel".to_string(), "v=DKIM1; k=rsa; p=BBBB".to_string()),
		],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(&full_config()),
		None,
		None,
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
