//! The supplied TXT records in the wanted set the publisher and
//! `dns-records` read.

use super::*;
use crate::dns::provider::RecordKind;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n{extra}"
	))
	.expect("config")
}

const SUPPLIED: &str = "[dns_publish]\nextra_txt = [{ name = 'example.org', value = 'google-site-verification=abc' }]\n";

#[test]
fn nothing_supplied_leaves_the_wanted_set_as_it_was() {
	let plain = from_config(&config("")).expect("set");
	let empty = from_config(&config("[dns_publish]\nextra_txt = []\n")).expect("set");
	assert_eq!(plain.records, empty.records);
	assert!(
		!plain
			.records
			.iter()
			.any(|r| r.record.value.contains("google-site-verification"))
	);
}

#[test]
fn a_supplied_txt_is_one_more_record_and_the_rest_is_unchanged() {
	let plain = from_config(&config("")).expect("set");
	let with = from_config(&config(SUPPLIED)).expect("set");
	assert_eq!(with.records.len(), plain.records.len() + 1);
	assert!(with.records.starts_with(&plain.records));
}

#[test]
fn the_supplied_txt_does_not_disturb_the_spf_at_the_same_name() {
	let with = from_config(&config(SUPPLIED)).expect("set");
	let apex: Vec<&str> = with
		.records
		.iter()
		.filter(|r| r.record.name == "example.org" && r.record.kind == RecordKind::Txt)
		.map(|r| r.record.value.as_str())
		.collect();
	assert_eq!(apex.len(), 2, "{apex:?}");
	assert!(apex.iter().any(|v| v.starts_with("v=spf1")), "{apex:?}");
	assert!(apex.contains(&"google-site-verification=abc"), "{apex:?}");
}

#[test]
fn a_supplied_txt_survives_a_second_computation() {
	let config = config(SUPPLIED);
	let first = from_config(&config).expect("set");
	let second = from_config(&config).expect("set");
	assert_eq!(first.records, second.records);
}
