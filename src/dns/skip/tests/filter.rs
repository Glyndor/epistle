//! The filter takes the skipped groups out of the wanted set and keeps them
//! apart, so the operator sees what was left out.

use super::super::*;
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::records::PublishRecord;

fn wanted(name: &str, kind: RecordKind, value: &str) -> PublishRecord {
	PublishRecord {
		zone: "example.org".into(),
		record: DnsRecord::new(name, kind, value, 3600),
	}
}

fn set() -> Vec<PublishRecord> {
	vec![
		wanted("example.org", RecordKind::Mx, "10 mail.example.org."),
		wanted(
			"_imaps._tcp.example.org",
			RecordKind::Srv,
			"0 1 993 mail.example.org.",
		),
		wanted("_mta-sts.example.org", RecordKind::Txt, "v=STSv1; id=1"),
		wanted(
			"_imap._tcp.example.org",
			RecordKind::Srv,
			"0 1 143 mail.example.org.",
		),
	]
}

#[test]
fn an_empty_skip_set_changes_nothing() {
	let (kept, skipped) = split_records(set(), &SkipSet::default());
	assert_eq!(kept.len(), 4);
	assert!(skipped.is_empty());
}

#[test]
fn skipped_groups_leave_the_set_and_keep_their_records() {
	let skip = SkipSet::new([SkipGroup::ClientLocators]);
	let (kept, skipped) = split_records(set(), &skip);
	let names: Vec<_> = kept.iter().map(|r| r.record.name.as_str()).collect();
	assert_eq!(names, ["example.org", "_mta-sts.example.org"]);
	assert_eq!(skipped.len(), 1);
	assert_eq!(skipped[0].group, SkipGroup::ClientLocators);
	assert_eq!(skipped[0].records.len(), 2);
}

#[test]
fn skipped_groups_are_listed_in_the_fixed_order_of_the_groups() {
	let skip = SkipSet::new([SkipGroup::MtaSts, SkipGroup::ClientLocators]);
	let (_, skipped) = split_records(set(), &skip);
	let groups: Vec<_> = skipped.iter().map(|entry| entry.group).collect();
	assert_eq!(groups, [SkipGroup::ClientLocators, SkipGroup::MtaSts]);
}

#[test]
fn a_ledger_record_of_a_skipped_group_is_retired_naming_the_group() {
	let record = DnsRecord::new(
		"_imaps._tcp.example.org",
		RecordKind::Srv,
		"0 1 993 mail.example.org.",
		3600,
	);
	let reason = SkipSet::new([SkipGroup::ClientLocators]).retirement_reason(&record);
	assert!(
		reason.contains("skips the client-locators group"),
		"{reason}"
	);
	let plain = SkipSet::default().retirement_reason(&record);
	assert!(plain.contains("no longer needs it"), "{plain}");
}
