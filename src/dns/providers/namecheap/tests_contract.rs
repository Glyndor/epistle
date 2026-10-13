//! The upsert contract against the Namecheap mock: a TXT upsert replaces
//! the record of the same purpose and leaves every other TXT at the name
//! alone. setHosts replaces the whole zone, so the upsert has to carry the
//! siblings it read.

use super::tests::{mock, txt};
use crate::dns::provider::DnsProvider;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

fn zone_with(values: &[&str]) -> String {
	let hosts: String = values
		.iter()
		.enumerate()
		.map(|(i, v)| {
			format!(
				r#"<host HostId="{i}" Name="sel._domainkey" Type="TXT" Address="{v}" TTL="3600"/>"#
			)
		})
		.collect();
	format!(
		r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org">{hosts}<host HostId="9" Name="@" Type="A" Address="192.0.2.1" TTL="1800"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#
	)
}

/// The TXT values the one setHosts call sent, sorted.
async fn upsert_over(existing: &[&str]) -> Vec<String> {
	let (provider, state) = mock(&zone_with(existing), None).await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.set_hosts_calls.len(), 1);
	let mut txt: Vec<String> = s.set_hosts_calls[0]
		.hosts()
		.into_iter()
		.filter(|h| h.kind == "TXT")
		.map(|h| h.address)
		.collect();
	txt.sort();
	txt
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let txt = upsert_over(&[SIBLING]).await;
	assert_eq!(txt, vec![SIBLING.to_string(), NEW_DKIM.to_string()]);
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let txt = upsert_over(&[SIBLING, OLD_DKIM]).await;
	assert_eq!(txt, vec![SIBLING.to_string(), NEW_DKIM.to_string()]);
}
