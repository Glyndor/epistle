//! The request shape against the mock of the documented API: getHosts and
//! setHosts as form POSTs with every global parameter, setHosts carrying the
//! whole zone in numbered parameters.

use super::tests::{SentHost, mock, txt};
use crate::dns::provider::DnsProvider;

const ZONE: &str = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org" IsUsingOurDNS="true"><host HostId="1" Name="@" Type="A" Address="192.0.2.1" MXPref="10" TTL="1800"/><host HostId="2" Name="@" Type="MX" Address="mail.example.org" MXPref="10" TTL="1800"/><host HostId="3" Name="www" Type="URL" Address="https://example.org/" MXPref="10" TTL="1800"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;

fn host(name: &str, kind: &str, address: &str, ttl: &str, mx_pref: Option<&str>) -> SentHost {
	SentHost {
		name: name.into(),
		kind: kind.into(),
		address: address.into(),
		ttl: Some(ttl.into()),
		mx_pref: mx_pref.map(str::to_string),
	}
}

/// setHosts replaces the whole host list, so the upsert sends every record
/// it read back alongside the new one, each with its own type, TTL and, for
/// MX, preference, and with `EmailType=MX` because the zone has MX hosts.
#[tokio::test]
async fn set_hosts_is_a_form_post_carrying_the_whole_zone() {
	let (provider, state) = mock(ZONE, None).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.set_hosts_calls.len(), 1, "setHosts not accepted");
	// getHosts for the read, then setHosts, both as forms.
	assert_eq!(
		s.post_content_types,
		vec!["application/x-www-form-urlencoded".to_string(); 2]
	);
	let call = &s.set_hosts_calls[0];
	for (key, value) in [
		("Command", "namecheap.domains.dns.setHosts"),
		("ApiUser", "user"),
		("UserName", "user"),
		("ApiKey", "key"),
		("ClientIp", "192.0.2.10"),
		("SLD", "example"),
		("TLD", "org"),
		("EmailType", "MX"),
	] {
		assert_eq!(call.param(key), Some(value), "{key}");
	}
	assert_eq!(
		call.hosts(),
		vec![
			host("@", "A", "192.0.2.1", "1800", None),
			host("@", "MX", "mail.example.org", "1800", Some("10")),
			host("www", "URL", "https://example.org/", "1800", None),
			host("_dmarc", "TXT", "v=DMARC1; p=none", "3600", None),
		]
	);
}

/// getHosts is a form POST like setHosts: the key travels in the body, and
/// the URL the request goes to carries no parameter at all.
#[tokio::test]
async fn get_hosts_is_a_form_post_and_the_url_carries_nothing() {
	let (provider, state) = mock(ZONE, None).await;
	provider.list("example.org").await.expect("list");
	let s = state.lock().unwrap();
	assert_eq!(s.urls, vec!["/xml.response".to_string()]);
	assert_eq!(
		s.post_content_types,
		vec!["application/x-www-form-urlencoded".to_string()]
	);
	let call = &s.get_hosts_calls[0];
	for (key, value) in [
		("Command", "namecheap.domains.dns.getHosts"),
		("ApiUser", "user"),
		("UserName", "user"),
		("ApiKey", "key"),
		("ClientIp", "192.0.2.10"),
		("SLD", "example"),
		("TLD", "org"),
	] {
		assert_eq!(call.get(key).map(String::as_str), Some(value), "{key}");
	}
}

/// The getHosts example in the documentation spells the element `Host`;
/// other clients read `host`. Both are read.
#[tokio::test]
async fn get_hosts_reads_either_spelling_of_the_host_element() {
	let documented = ZONE.replace("<host ", "<Host ");
	let (provider, _state) = mock(&documented, None).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 2, "{records:?}");
}
