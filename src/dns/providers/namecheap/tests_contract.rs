//! The upsert contract against the Namecheap mock: a TXT upsert replaces
//! the record of the same purpose and leaves every other TXT at the name
//! alone. setHosts replaces the whole zone, so the upsert has to carry the
//! siblings it read.

use super::tests::{mock, txt};
use crate::dns::provider::DnsProvider;
use crate::dns::providers::listing_contract::{
	CAA_VALUE, HTTPS_VALUE, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE, SVCB_VALUE, Shape,
	assert_kinds_kept,
};
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

/// Two SPF records at the apex plus one unrelated TXT is a
/// configuration mistake every receiver turns into a permanent
/// error: SPF returns `permerror` (RFC 7208 §4.5). The upsert
/// must collapse the two SPF entries into one carrying the new
/// value, leave the unrelated TXT alone, and never create a
/// third record.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let initial = format!(
		r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="1" Name="@" Type="TXT" Address="{OLD_SPF_1}" TTL="3600"/><host HostId="2" Name="@" Type="TXT" Address="{OLD_SPF_2}" TTL="3600"/><host HostId="3" Name="@" Type="TXT" Address="{UNRELATED}" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#
	);
	let (provider, state) = mock(&initial, None).await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let s = state.lock().unwrap();
	assert_eq!(s.set_hosts_calls.len(), 1);
	let mut txt: Vec<String> = s.set_hosts_calls[0]
		.hosts()
		.into_iter()
		.filter(|h| h.kind == "TXT" && h.name == "@")
		.map(|h| h.address)
		.collect();
	txt.sort();
	let mut expected = vec![NEW_SPF.to_string(), UNRELATED.to_string()];
	expected.sort();
	assert_eq!(
		txt, expected,
		"the new setHosts body must carry exactly one SPF (new) and the unrelated TXT"
	);
	// No old SPF value reaches the wire.
	for old in [OLD_SPF_1, OLD_SPF_2] {
		assert!(
			!txt.contains(&old.to_string()),
			"old SPF value {old:?} re-published"
		);
	}
}

/// A zone with a delegated subdomain and records of types epistle does not
/// publish lists every one of them with its own kind: nothing is turned into
/// a TXT, and a type token that is not a record type comes back as
/// `UNKNOWN`.
/// Namecheap's `getHosts` answers XML, so the escape-laden type token of the
/// shared zone is written with characters XML allows, and the provider
/// trims the root dot of a hostname value.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let host = |id: u32, name: &str, kind: &str, address: &str| {
		format!(
			r#"<host HostId="{id}" Name="{name}" Type="{kind}" Address="{}" TTL="3600"/>"#,
			address.replace('"', "&quot;")
		)
	};
	let hosts = [
		host(1, "sub", "NS", NS_TARGET),
		host(2, "@", "CAA", CAA_VALUE),
		host(3, "@", "HTTPS", HTTPS_VALUE),
		host(4, "@", "SVCB", SVCB_VALUE),
		host(5, "@", "NAPTR", NAPTR_VALUE),
		host(6, "@", "NAPTR X!", OPAQUE_VALUE),
	]
	.concat();
	let xml = format!(
		r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org">{hosts}</DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#
	);
	let (provider, _state) = mock(&xml, None).await;
	let listed = provider.list("example.org").await.expect("list");
	let shape = Shape {
		trailing_dot: false,
		..Shape::NAMED
	};
	assert_kinds_kept(&listed, &shape);
}
