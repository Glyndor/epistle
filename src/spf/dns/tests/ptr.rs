//! Reverse lookups through [`SystemDns`] against an in-process resolver.
//!
//! Most reverse zones are unsigned, and some that are (deep `ip6.arpa`
//! delegations behind empty non-terminals) fail hickory's DNSSEC proof of
//! insecurity even though a validating `delv` reads them as plain unsigned
//! answers. Nobody trusts a PTR because of DNSSEC, so a reverse lookup must
//! not depend on validation: the fake server below never signs anything,
//! the way most of the reverse tree behaves.

use std::collections::HashMap;
use std::net::IpAddr;

use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::PTR;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

use super::DnsLookup;
use super::server::{self, Reply};

/// `2001:db8::25` in the `ip6.arpa` nibble format (RFC 3596 §2.5): the 32
/// hex digits of the address, least significant first, one label each.
const V6_REVERSE: &str =
	"5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
const V4_REVERSE: &str = "25.2.0.192.in-addr.arpa.";

/// Answer the PTR queries for the names in `zone` and everything else with an
/// empty NOERROR. Returns the listening port.
async fn spawn_resolver(zone: HashMap<&'static str, &'static str>) -> u16 {
	server::spawn(move |query: &Message| {
		let Some(question) = query.queries.first() else {
			return Reply::Answers(Vec::new());
		};
		if question.query_type() != RecordType::PTR {
			return Reply::Answers(Vec::new());
		}
		let asked = question.name().to_ascii().to_ascii_lowercase();
		let Some(target) = zone.get(asked.as_str()) else {
			return Reply::Answers(Vec::new());
		};
		let target = Name::from_ascii(target).expect("target name");
		Reply::Answers(vec![Record::from_rdata(
			question.name().clone(),
			300,
			RData::PTR(PTR(target)),
		)])
	})
	.await
}

#[tokio::test]
async fn an_unsigned_ptr_resolves_for_ipv6_like_for_ipv4() {
	let port = spawn_resolver(HashMap::from([
		(V6_REVERSE, "mail.example.org."),
		(V4_REVERSE, "mail.example.org."),
	]))
	.await;
	let dns = server::resolver(port);
	for address in ["2001:db8::25", "192.0.2.25"] {
		let ip: IpAddr = address.parse().expect("address");
		let found = tokio::time::timeout(std::time::Duration::from_secs(20), dns.ptr(ip))
			.await
			.expect("the lookup finishes");
		assert_eq!(
			found,
			Ok(vec!["mail.example.org".to_string()]),
			"PTR of {address} through the system resolver"
		);
	}
}

#[tokio::test]
async fn an_address_without_ptr_has_no_names() {
	let port = spawn_resolver(HashMap::new()).await;
	let dns = server::resolver(port);
	let ip: IpAddr = "2001:db8::25".parse().expect("address");
	let found = tokio::time::timeout(std::time::Duration::from_secs(20), dns.ptr(ip))
		.await
		.expect("the lookup finishes");
	assert_eq!(found, Ok(Vec::new()), "PTR of an address with none");
}
