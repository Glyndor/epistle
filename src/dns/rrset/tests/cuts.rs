//! The delegations of a zone: an NS rrset below the apex hands that name
//! and everything under it to other nameservers, so nothing epistle writes
//! there would ever be answered. The NS rrset of the apex is not a
//! delegation, and neither is an NS at a wildcard (RFC 4592).

use super::*;
use crate::dns::names::MAX_NAME_LEN;
use crate::dns::provider::{DnsRecord, RecordKind};

fn ns(name: &str) -> DnsRecord {
	DnsRecord::new(name, RecordKind::Ns, "ns1.delegated.example.", 3600)
}

#[test]
fn the_cut_that_covers_a_name_is_the_highest_one() {
	let existing = [ns("sub.example.org"), ns("a.sub.example.org")];
	let cuts = Cuts::new("example.org", &existing);
	assert_eq!(cuts.above("x.a.sub.example.org"), Some("sub.example.org"));
	assert_eq!(cuts.above("a.sub.example.org"), Some("sub.example.org"));
	assert_eq!(cuts.above("sub.example.org"), Some("sub.example.org"));
	assert_eq!(cuts.above("example.org"), None);
	assert_eq!(cuts.above("www.example.org"), None);
	assert_eq!(cuts.above("subexample.org"), None);
	assert_eq!(cuts.above("sub.example.org.evil.net"), None);
	let too_long = format!("{}sub.example.org", "a.".repeat(130));
	assert!(too_long.len() > MAX_NAME_LEN);
	assert_eq!(
		cuts.above(&too_long),
		None,
		"a name past the DNS limit is not searched"
	);
}

#[test]
fn the_ns_records_of_the_apex_are_not_a_delegation() {
	let existing = [ns("example.org")];
	let cuts = Cuts::new("example.org", &existing);
	assert_eq!(cuts.above("www.example.org"), None);
	assert!(cuts.relevant_to("example.org").is_empty());
}
