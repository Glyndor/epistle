//! Basic-flow tests for the Namecheap provider: upsert, delete, list, and
//! URL/auth wiring.

use super::NamecheapProvider;
use super::tests::{mock, txt};
use crate::dns::provider::{DnsProvider, ProviderError, RecordKind, ScopedSecret};

#[tokio::test]
async fn upsert_creates_when_absent() {
	let (provider, state) = mock("", None).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let captured = state.lock().unwrap();
	assert_eq!(captured.set_hosts_calls.len(), 1, "setHosts not called");
	let hosts = captured.set_hosts_calls[0].hosts();
	assert_eq!(hosts.len(), 1, "{hosts:?}");
	assert_eq!(hosts[0].name, "_dmarc");
	assert_eq!(hosts[0].kind, "TXT");
	// TXT goes as its logical value, unquoted.
	assert_eq!(hosts[0].address, "v=DMARC1; p=none");
}

#[tokio::test]
async fn upsert_updates_when_present() {
	let existing = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="abc" Name="_dmarc" Type="TXT" Address="&quot;v=DMARC1; p=none&quot;" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, state) = mock(existing, None).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let hosts = state.lock().unwrap().set_hosts_calls[0].hosts();
	let addresses: Vec<&str> = hosts.iter().map(|h| h.address.as_str()).collect();
	assert!(
		!addresses.contains(&"\"old\""),
		"old value leaked: {hosts:?}"
	);
	assert!(
		addresses.contains(&"v=DMARC1; p=reject"),
		"new value missing: {hosts:?}"
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
		captured.set_hosts_calls.is_empty(),
		"setHosts called unexpectedly: {:?}",
		captured.set_hosts_calls
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
	let s = state.lock().unwrap();
	assert_eq!(s.set_hosts_calls.len(), 1, "setHosts not called");
	let hosts = s.set_hosts_calls[0].hosts();
	assert!(hosts.is_empty(), "record still sent: {hosts:?}");
}

/// A TXT delete with a value must remove only the matching record
/// and keep sibling TXT records at the same owner. Two ACME DNS-01
/// challenges at the same owner is the canonical case: cleaning up
/// one certificate order's challenge must not wipe the second
/// order's challenge. Namecheap's `setHosts` replaces the whole
/// zone, so the fix is to read the live set, drop the host whose
/// value matches, and PUT the rest.
#[tokio::test]
async fn txt_delete_with_a_value_keeps_the_sibling_challenge() {
	let existing = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="aa" Name="_acme-challenge" Type="TXT" Address="&quot;token-aaaa&quot;" TTL="60"/><host HostId="bb" Name="_acme-challenge" Type="TXT" Address="&quot;token-bbbb&quot;" TTL="60"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, state) = mock(existing, None).await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let hosts = state.lock().unwrap().set_hosts_calls[0].hosts();
	let addresses: Vec<&str> = hosts.iter().map(|h| h.address.as_str()).collect();
	assert_eq!(addresses, vec!["\"token-bbbb\""], "{hosts:?}");
}

#[tokio::test]
async fn tlsa_returns_unsupported_without_network() {
	let (provider, state) = mock("", None).await;
	let tlsa = crate::dns::provider::DnsRecord {
		name: "_25._tcp.mail.example.org".into(),
		kind: RecordKind::Tlsa,
		value: "3 0 1 abcd".into(),
		ttl: 3600,
		proxied: None,
	};
	let result = provider.upsert("example.org", tlsa).await;
	assert_eq!(result, Err(ProviderError::Unsupported));
	assert!(state.lock().unwrap().urls.is_empty(), "made network call");
}

/// MX goes with its preference in `MXPref{n}`. SRV is not among the record
/// types setHosts documents, so it is refused before any network call.
#[tokio::test]
async fn mx_is_supported_and_srv_refused() {
	let (provider, state) = mock("", None).await;
	let mx = crate::dns::provider::DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", mx).await.expect("mx upsert");
	let srv = crate::dns::provider::DnsRecord {
		name: "_sip._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "10 5 5060 sip.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	assert_eq!(
		provider.upsert("example.org", srv).await,
		Err(ProviderError::Unsupported)
	);
	let captured = state.lock().unwrap();
	assert_eq!(captured.set_hosts_calls.len(), 1);
	let call = &captured.set_hosts_calls[0];
	let mx = &call.hosts()[0];
	assert_eq!(
		(mx.name.as_str(), mx.kind.as_str(), mx.address.as_str()),
		("@", "MX", "mail.example.org")
	);
	assert_eq!(mx.mx_pref.as_deref(), Some("10"));
	assert_eq!(call.param("EmailType"), Some("MX"));
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
	assert_eq!(first, "/xml.response", "base url not honoured");
}

#[tokio::test]
async fn auth_params_include_username_and_key() {
	let (provider, state) = mock("", None).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	for call in s
		.get_hosts_calls
		.iter()
		.chain(s.set_hosts_calls.iter().map(|c| &c.params))
	{
		for (key, value) in [
			("ApiUser", "user"),
			("UserName", "user"),
			("ApiKey", "key"),
			("SLD", "example"),
			("TLD", "org"),
		] {
			assert_eq!(call.get(key).map(String::as_str), Some(value), "{key}");
		}
	}
	assert_eq!((s.get_hosts_calls.len(), s.set_hosts_calls.len()), (1, 1));
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
async fn unknown_kind_in_list_keeps_its_own_kind() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="a" Name="@" Type="A" Address="1.2.3.4" TTL="3600"/><host HostId="b" Name="@" Type="URLFRAME" Address="https://x.example/" TTL="300"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, _state) = mock(xml, None).await;
	let records = provider.list("example.org").await.expect("list");
	let kinds: Vec<RecordKind> = records.iter().map(|r| r.kind.clone()).collect();
	assert_eq!(
		kinds,
		vec![RecordKind::A, RecordKind::Other("URLFRAME".to_string())],
		"URLFRAME is not a record epistle publishes, and it is not a TXT either"
	);
	assert_eq!(records[1].value, "https://x.example/");
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
