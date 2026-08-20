//! Basic-flow tests for the Namecheap provider: upsert, delete, list, and
//! URL/auth wiring.

use super::super::provider::{DnsProvider, ProviderError, RecordKind, ScopedSecret};
use super::NamecheapProvider;
use super::tests::{mock, txt};

#[tokio::test]
async fn upsert_creates_when_absent() {
	let (provider, state) = mock("", None).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let captured = state.lock().unwrap();
	assert_eq!(captured.set_hosts_bodies.len(), 1, "setHosts not called");
	let body = &captured.set_hosts_bodies[0];
	assert!(body.contains(r#"Name="_dmarc""#), "{body}");
	assert!(body.contains(r#"Type="TXT""#), "{body}");
	assert!(
		body.contains(r#"Address="&quot;v=DMARC1; p=none&quot;""#),
		"{body}"
	);
}

#[tokio::test]
async fn upsert_updates_when_present() {
	let existing = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="abc" Name="_dmarc" Type="TXT" Address="&quot;old&quot;" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, state) = mock(existing, None).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let body = state.lock().unwrap().set_hosts_bodies[0].clone();
	assert!(
		!body.contains("p=none") && !body.contains("&quot;old&quot;"),
		"old value leaked: {body}"
	);
	assert!(
		body.contains("v=DMARC1; p=reject"),
		"new value missing: {body}"
	);
}

#[tokio::test]
async fn delete_idempotent_when_absent() {
	let (provider, state) = mock("", None).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let captured = state.lock().unwrap();
	assert!(
		captured.set_hosts_bodies.is_empty(),
		"setHosts called unexpectedly: {:?}",
		captured.set_hosts_bodies
	);
}

#[tokio::test]
async fn delete_removes_record() {
	let existing = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="abc" Name="_dmarc" Type="TXT" Address="&quot;old&quot;" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, state) = mock(existing, None).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "old"))
		.await
		.expect("delete");
	let body = state.lock().unwrap().set_hosts_bodies[0].clone();
	assert!(!body.contains("_dmarc"), "record still in body: {body}");
	assert!(!body.contains("<host"), "record still in body: {body}");
}

#[tokio::test]
async fn tlsa_returns_unsupported_without_network() {
	let (provider, state) = mock("", None).await;
	let tlsa = super::super::provider::DnsRecord {
		name: "_25._tcp.mail.example.org".into(),
		kind: RecordKind::Tlsa,
		value: "3 0 1 abcd".into(),
		ttl: 3600,
	};
	let result = provider.upsert("example.org", tlsa).await;
	assert_eq!(result, Err(ProviderError::Unsupported));
	assert!(state.lock().unwrap().urls.is_empty(), "made network call");
}

#[tokio::test]
async fn mx_and_srv_supported() {
	let (provider, state) = mock("", None).await;
	let mx = super::super::provider::DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", mx).await.expect("mx upsert");
	let srv = super::super::provider::DnsRecord {
		name: "_sip._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "10 5 5060 sip.example.org".into(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", srv)
		.await
		.expect("srv upsert");
	let captured = state.lock().unwrap();
	let mx_body = &captured.set_hosts_bodies[0];
	let srv_body = &captured.set_hosts_bodies[1];
	assert!(
		mx_body.contains(r#"Name="@" Type="MX" Address="mail.example.org" MXPref="10""#),
		"{mx_body}"
	);
	assert!(
		srv_body.contains(
			r#"Name="_sip._tcp" Type="SRV" Address="sip.example.org" Priority="10" Weight="5" Port="5060""#
		),
		"{srv_body}"
	);
}

#[tokio::test]
async fn sandbox_url_flows_through() {
	let (provider, state) = mock("", None).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let captured = state.lock().unwrap();
	assert!(!captured.urls.is_empty());
	let first = &captured.urls[0];
	assert!(
		first.contains("/xml.response?ApiUser="),
		"base url not honoured: {first}"
	);
}

#[tokio::test]
async fn auth_params_include_username_and_key() {
	let (provider, state) = mock("", None).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let url = state.lock().unwrap().urls[0].clone();
	assert!(
		url.contains("ApiUser=user") && url.contains("UserName=user"),
		"missing username params: {url}"
	);
	assert!(url.contains("ApiKey=key"), "missing api key param: {url}");
	assert!(
		url.contains("SLD=example") && url.contains("TLD=org"),
		"{url}"
	);
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock("", None).await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().urls.is_empty());
}

#[tokio::test]
async fn list_with_srvs_and_incomplete_records_skips_malformed() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="d" Name="_sip._tcp" Type="SRV" Address="sip.example.org" Priority="10" Weight="5" Port="5060" TTL="3600"/><host HostId="e" Name="_bad._tcp" Type="SRV" Address="x.example.org" TTL="3600"/><host HostId="f" Name="@" Type="MX" Address="m.example.org" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, _state) = mock(xml, None).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(
		records.len(),
		1,
		"only the complete SRV should survive: {records:?}"
	);
	assert_eq!(records[0].kind, RecordKind::Srv);
	assert_eq!(records[0].value, "10 5 5060 sip.example.org");
}

#[tokio::test]
async fn list_without_hosts_result_block_returns_empty() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"/></ApiResponse>"#;
	let (provider, _state) = mock(xml, None).await;
	let records = provider.list("example.org").await.expect("list");
	assert!(records.is_empty());
}

#[tokio::test]
async fn api_response_without_command_response_still_extracts_empty_hosts() {
	let xml =
		r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/></ApiResponse>"#;
	let (provider, _state) = mock(xml, None).await;
	let records = provider.list("example.org").await.expect("list");
	assert!(records.is_empty());
}

#[tokio::test]
async fn unknown_kind_in_list_is_skipped() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="a" Name="@" Type="A" Address="1.2.3.4" TTL="3600"/><host HostId="b" Name="@" Type="URLFRAME" Address="https://x.example/" TTL="300"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, _state) = mock(xml, None).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 1, "URLFRAME should be skipped: {records:?}");
	assert_eq!(records[0].kind, RecordKind::A);
}

#[tokio::test]
async fn list_round_trips_records() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="a" Name="@" Type="A" Address="1.2.3.4" TTL="3600"/><host HostId="b" Name="@" Type="MX" Address="mail.example.org" MXPref="10" TTL="3600"/><host HostId="c" Name="_dmarc" Type="TXT" Address="&quot;v=DMARC1&quot;" TTL="3600"/><host HostId="d" Name="_sip._tcp" Type="SRV" Address="sip.example.org" Priority="10" Weight="5" Port="5060" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, _state) = mock(xml, None).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 4, "got {records:?}");
	let apex_a = records
		.iter()
		.find(|r| r.kind == RecordKind::A && r.name == "example.org")
		.expect("apex A");
	assert_eq!(apex_a.value, "1.2.3.4");
	let apex_mx = records
		.iter()
		.find(|r| r.kind == RecordKind::Mx)
		.expect("mx");
	assert_eq!(apex_mx.value, "10 mail.example.org");
	let dmarc = records
		.iter()
		.find(|r| r.kind == RecordKind::Txt)
		.expect("txt");
	assert_eq!(dmarc.name, "_dmarc.example.org");
	assert_eq!(dmarc.value, "v=DMARC1");
	let srv = records
		.iter()
		.find(|r| r.kind == RecordKind::Srv)
		.expect("srv");
	assert_eq!(srv.name, "_sip._tcp.example.org");
	assert_eq!(srv.value, "10 5 5060 sip.example.org");
}

#[tokio::test]
async fn new_rejects_token_without_colon() {
	let secret = ScopedSecret::new("example.org", "nocolon");
	assert!(matches!(
		NamecheapProvider::new(secret),
		Err(ProviderError::Auth)
	));
}

#[tokio::test]
async fn new_rejects_empty_username_or_key() {
	assert!(matches!(
		NamecheapProvider::new(ScopedSecret::new("example.org", ":key")),
		Err(ProviderError::Auth)
	));
	assert!(matches!(
		NamecheapProvider::new(ScopedSecret::new("example.org", "user:")),
		Err(ProviderError::Auth)
	));
}
