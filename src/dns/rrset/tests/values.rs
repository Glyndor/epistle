//! The comparable form of a value. A provider spells a target in its own
//! way: with the trailing root dot, in upper case, or split into character
//! strings. Two providers that hold the same record have to agree on it,
//! and a target that differs in anything else is another record.

use super::*;
use crate::dns::provider::{DnsRecord, RecordKind};

fn srv(value: &str) -> DnsRecord {
	DnsRecord::new("_sieve._tcp.example.org", RecordKind::Srv, value, 3600)
}

fn cname(value: &str) -> DnsRecord {
	DnsRecord::new("autodiscover.example.org", RecordKind::Cname, value, 3600)
}

#[test]
fn an_srv_target_compares_without_its_root_dot_or_its_case() {
	assert_eq!(
		canonical_value(&RecordKind::Srv, "0 1 4190 Mail.Example.ORG."),
		canonical_value(&RecordKind::Srv, "0 1 4190 mail.example.org")
	);
}

#[test]
fn an_srv_with_another_port_or_priority_is_another_record() {
	assert_ne!(
		canonical_value(&RecordKind::Srv, "0 1 4190 mail.example.org."),
		canonical_value(&RecordKind::Srv, "0 1 465 mail.example.org.")
	);
	assert_ne!(
		canonical_value(&RecordKind::Srv, "0 1 4190 mail.example.org."),
		canonical_value(&RecordKind::Srv, "10 1 4190 mail.example.org.")
	);
}

#[test]
fn a_cname_target_compares_without_its_root_dot_or_its_case() {
	assert_eq!(
		canonical_value(&RecordKind::Cname, "Mail.Example.ORG."),
		canonical_value(&RecordKind::Cname, "mail.example.org")
	);
}

#[test]
fn the_same_srv_written_two_ways_is_the_same_record() {
	assert!(same_typed_record(
		&srv("0 1 4190 Mail.Example.ORG."),
		&srv("0 1 4190 mail.example.org")
	));
	assert!(same_typed_record(
		&cname("Mail.Example.ORG."),
		&cname("mail.example.org")
	));
}

#[test]
fn a_record_with_another_ttl_or_proxy_state_is_another_record() {
	let ours = srv("0 1 4190 mail.example.org.");
	let mut another_ttl = ours.clone();
	another_ttl.ttl = 60;
	assert!(!same_typed_record(&ours, &another_ttl));
	let mut proxied = ours.clone();
	proxied.proxied = Some(true);
	assert!(!same_typed_record(&ours, &proxied));
}

#[test]
fn a_record_of_another_name_or_kind_is_another_record() {
	let ours = srv("0 1 4190 mail.example.org.");
	let mut elsewhere = ours.clone();
	elsewhere.name = "_imaps._tcp.example.org".to_string();
	assert!(!same_typed_record(&ours, &elsewhere));
	let mut other_kind = ours.clone();
	other_kind.kind = RecordKind::Cname;
	assert!(!same_typed_record(&ours, &other_kind));
}
