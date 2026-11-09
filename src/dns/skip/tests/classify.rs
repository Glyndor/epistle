//! Which group a record belongs to; the core records belong to none.

use super::super::*;
use crate::dns::provider::{DnsRecord, RecordKind};

fn rec(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord::new(name, kind, value, 3600)
}

#[test]
fn every_record_of_a_group_is_classified_into_it() {
	for (record, group) in [
		(
			rec(
				"_imaps._tcp.example.org",
				RecordKind::Srv,
				"0 1 993 mail.example.org.",
			),
			SkipGroup::ClientLocators,
		),
		(
			rec(
				"autoconfig.example.org",
				RecordKind::Cname,
				"mail.example.org.",
			),
			SkipGroup::ClientLocators,
		),
		(
			rec(
				"Autodiscover.Example.ORG.",
				RecordKind::Cname,
				"mail.example.org.",
			),
			SkipGroup::ClientLocators,
		),
		(
			rec("_mta-sts.example.org", RecordKind::Txt, "v=STSv1; id=1"),
			SkipGroup::MtaSts,
		),
		(
			rec(
				"mta-sts.example.org",
				RecordKind::Cname,
				"mail.example.org.",
			),
			SkipGroup::MtaSts,
		),
		(
			rec(
				"_smtp._tls.example.org",
				RecordKind::Txt,
				"v=TLSRPTv1; rua=mailto:t@example.org",
			),
			SkipGroup::TlsRpt,
		),
		(
			rec("_25._tcp.mail.example.org", RecordKind::Tlsa, "3 1 1 00"),
			SkipGroup::Tlsa,
		),
		(
			rec(
				"example.org",
				RecordKind::Caa,
				"0 issue \"letsencrypt.org\"",
			),
			SkipGroup::Caa,
		),
	] {
		assert_eq!(group_of_record(&record), Some(group), "{record:?}");
	}
}

#[test]
fn the_core_records_are_in_no_group_and_can_never_be_skipped() {
	let everything = SkipSet::new(SkipGroup::ALL);
	for record in [
		rec("example.org", RecordKind::Mx, "10 mail.example.org."),
		rec("example.org", RecordKind::Txt, "v=spf1 mx -all"),
		rec("_dmarc.example.org", RecordKind::Txt, "v=DMARC1; p=none"),
		rec(
			"sel._domainkey.example.org",
			RecordKind::Txt,
			"v=DKIM1; k=ed25519; p=AA",
		),
		rec("mail.example.org", RecordKind::A, "192.0.2.1"),
		rec("mail.example.org", RecordKind::Aaaa, "2001:db8::1"),
	] {
		assert_eq!(group_of_record(&record), None, "{record:?}");
		assert_eq!(everything.group_of(&record), None, "{record:?}");
	}
}

#[test]
fn a_set_skips_only_the_groups_it_names() {
	let set = SkipSet::new([SkipGroup::TlsRpt]);
	let tls_rpt = rec("_smtp._tls.example.org", RecordKind::Txt, "v=TLSRPTv1");
	let mta_sts = rec("_mta-sts.example.org", RecordKind::Txt, "v=STSv1; id=1");
	assert_eq!(set.group_of(&tls_rpt), Some(SkipGroup::TlsRpt));
	assert_eq!(set.group_of(&mta_sts), None);
	assert!(SkipSet::default().is_empty());
}
