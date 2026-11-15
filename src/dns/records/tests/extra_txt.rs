//! The TXT records the operator supplies join the wanted set.

use super::*;
use crate::config::ExtraTxt;

fn extra(name: &str, value: &str) -> ExtraTxt {
	ExtraTxt {
		name: name.into(),
		value: value.into(),
	}
}

fn domains(names: &[&str]) -> Vec<String> {
	names.iter().map(|name| name.to_string()).collect()
}

#[test]
fn a_supplied_txt_joins_the_wanted_set() {
	let records = extra_txt_records(
		&domains(&["example.org"]),
		&[extra("Example.ORG.", "google-site-verification=abc")],
	);
	assert_eq!(records.len(), 1, "{records:?}");
	assert_eq!(records[0].zone, "example.org");
	assert_eq!(records[0].record.name, "example.org");
	assert_eq!(records[0].record.kind, RecordKind::Txt);
	assert_eq!(records[0].record.value, "google-site-verification=abc");
}

#[test]
fn the_zone_is_the_longest_hosted_domain_that_holds_the_name() {
	let records = extra_txt_records(
		&domains(&["example.org", "mail.example.org"]),
		&[
			extra("_g.mail.example.org", "a"),
			extra("_g.example.org", "b"),
			extra("mail.example.org", "c"),
		],
	);
	let zones: Vec<&str> = records.iter().map(|r| r.zone.as_str()).collect();
	assert_eq!(
		zones,
		["mail.example.org", "example.org", "mail.example.org"]
	);
}

#[test]
fn a_name_no_hosted_domain_holds_is_left_out() {
	let records = extra_txt_records(
		&domains(&["example.org"]),
		&[
			extra("other.example.net", "a"),
			extra("notexample.org", "b"),
			extra("example.org", "c"),
		],
	);
	assert_eq!(records.len(), 1, "{records:?}");
	assert_eq!(records[0].record.value, "c");
}

#[test]
fn no_entry_gives_no_record() {
	assert!(extra_txt_records(&domains(&["example.org"]), &[]).is_empty());
}
