//! The set a domain needs, as the reconcile loop and `status` read it.

use crate::dns::lockdown::tests::support::*;
use crate::dns::lockdown::{NullSet, ServedNames, null_set};
use crate::dns::provider::{DnsRecord, RecordKind};

fn set_for(domain: &str, existing: &[DnsRecord], ours: &[DnsRecord]) -> NullSet {
	let served = ServedNames::new(&[domain.to_string()], "mail.example.org", existing);
	null_set("example.org", domain, &served, existing, ours)
}

fn null_spf(name: &str) -> DnsRecord {
	txt(name, "v=spf1 -all")
}

fn null_mx(name: &str) -> DnsRecord {
	mx(name, "0 .")
}

#[test]
fn a_name_without_the_records_is_uncovered_and_needed() {
	let set = set_for("example.org", &[a("www.example.org")], &[]);
	assert!(set.uncovered.contains(&"www.example.org".to_string()));
	assert!(set.uncovered.contains(&"*.example.org".to_string()));
	assert!(set.needed.contains(&null_spf("www.example.org")));
	assert!(set.needed.contains(&null_mx("www.example.org")));
}

#[test]
fn records_epistle_published_are_still_needed_and_no_longer_uncovered() {
	let ours = [
		null_spf("www.example.org"),
		null_mx("www.example.org"),
		null_spf("*.example.org"),
	];
	let mut existing = vec![a("www.example.org")];
	existing.extend(ours.iter().cloned());
	let set = set_for("example.org", &existing, &ours);
	assert!(set.uncovered.is_empty(), "{:?}", set.uncovered);
	for record in &ours {
		assert!(set.needed.contains(record), "{record:?}");
	}
}

#[test]
fn a_domain_inside_a_delegation_needs_nothing() {
	let existing = [
		rec("sub.example.org", RecordKind::Ns, "ns.elsewhere.test"),
		a("www.sub.example.org"),
	];
	let set = set_for("sub.example.org", &existing, &[]);
	assert_eq!(set, NullSet::default());
}
