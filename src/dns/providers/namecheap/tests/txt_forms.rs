//! TXT encoding against the Namecheap mock: what each fixture puts in a
//! host's `Address`, and the publish, list and compare round trip.

use super::super::render::host_from_record;
use super::base::{mock, txt};
use crate::dns::provider::DnsProvider;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::same_txt_value;

const NAME: &str = "sel._domainkey.example.org";

fn sent(value: &str) -> String {
	host_from_record(&txt(NAME, value), "example.org")
		.expect("host")
		.address
}

/// A getHosts answer holding one TXT host at `sel._domainkey`, with
/// `address` XML-escaped into the attribute the way the API sends it.
fn zone_with(address: &str) -> String {
	let attr = address
		.replace('&', "&amp;")
		.replace('"', "&quot;")
		.replace('<', "&lt;");
	format!(
		r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="7" Name="sel._domainkey" Type="TXT" Address="{attr}" TTL="3600"/><host HostId="8" Name="sel._domainkey" Type="TXT" Address="token-sibling" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#
	)
}

#[test]
fn txt_short_value_is_sent_unquoted() {
	assert_eq!(sent(SHORT), SHORT);
}

#[test]
fn txt_dkim_rsa2048_is_sent_whole_and_unquoted() {
	assert_eq!(sent(&dkim_rsa2048()), dkim_rsa2048());
}

#[test]
fn txt_quote_and_backslash_are_sent_as_they_are() {
	assert_eq!(sent(SPECIAL), SPECIAL);
}

#[test]
fn txt_caller_quoted_value_is_sent_without_the_quotes() {
	assert_eq!(sent(CALLER_QUOTED), CALLER_QUOTED_LOGICAL);
}

/// getHosts returns `Address` the way setHosts wrote it. Listing gives the
/// logical value back, and a delete by the logical value drops that host
/// and keeps its sibling.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let (provider, state) = mock(&zone_with(&sent(&value)), None).await;
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider
			.delete("example.org", txt(NAME, &logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		assert_eq!(s.set_hosts_calls.len(), 1, "{value}");
		let hosts = s.set_hosts_calls[0].hosts();
		assert_eq!(hosts.len(), 1, "{value}: {hosts:?}");
		assert_eq!(hosts[0].address, "token-sibling", "{value}");
	}
}
