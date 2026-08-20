//! Error-path tests for the Namecheap provider: HTTP errors, Namecheap-level
//! `<ApiResponse Status="ERROR">` bodies, oversize response bodies, malformed
//! XML, and malformed record values.

use super::super::provider::{DnsProvider, ProviderError, RecordKind};
use super::tests::{mock, txt};

#[tokio::test]
async fn unauthorized_response_401_returns_auth_error() {
	let (provider, _state) = mock("", Some((401, "".to_string()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
}

#[tokio::test]
async fn unauthorized_response_403_returns_auth_error() {
	let existing = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"><host HostId="abc" Name="@" Type="TXT" Address="&quot;x&quot;" TTL="3600"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#;
	let (provider, _state) = mock(existing, Some((403, "".to_string()))).await;
	let result = provider
		.delete("example.org", txt("example.org", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
}

#[tokio::test]
async fn server_error_500_surfaces_as_remote() {
	let (provider, _state) = mock("", Some((500, "internal error".into()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert!(
		matches!(result, Err(ProviderError::Remote(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn client_error_404_surfaces_as_remote() {
	let (provider, _state) = mock("", Some((404, "not found".into()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert!(
		matches!(result, Err(ProviderError::Remote(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn xml_parse_error_returns_remote_error() {
	let malformed = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><nope"#;
	let (provider, _state) = mock(malformed, None).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert!(
		matches!(result, Err(ProviderError::Remote(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn api_response_status_error_with_known_auth_number_returns_auth() {
	let err_xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="ERROR"><Errors><Error Number="1012801">IP not whitelisted</Error></Errors></ApiResponse>"#;
	let (provider, _state) = mock("", Some((200, err_xml.into()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
}

#[tokio::test]
async fn api_response_status_error_with_other_number_returns_remote_with_text() {
	let err_xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="ERROR"><Errors><Error Number="9999999">some failure</Error></Errors></ApiResponse>"#;
	let (provider, _state) = mock("", Some((200, err_xml.into()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	match result {
		Err(ProviderError::Remote(msg)) => assert!(msg.contains("some failure"), "{msg}"),
		other => panic!("expected Remote with text, got {other:?}"),
	}
}

#[tokio::test]
async fn api_response_status_error_with_empty_text_falls_back_to_number() {
	let err_xml = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="ERROR"><Errors><Error Number="9999999"></Error></Errors></ApiResponse>"#;
	let (provider, _state) = mock("", Some((200, err_xml.into()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	match result {
		Err(ProviderError::Remote(msg)) => assert!(msg.contains("9999999"), "{msg}"),
		other => panic!("expected Remote with number, got {other:?}"),
	}
}

#[tokio::test]
async fn api_response_status_error_with_no_errors_block_returns_remote() {
	let err_xml =
		r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="ERROR"></ApiResponse>"#;
	let (provider, _state) = mock("", Some((200, err_xml.into()))).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert!(
		matches!(result, Err(ProviderError::Remote(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn body_read_oversize_caps_at_limit() {
	let oversize = "x".repeat(256 * 1024 + 1);
	let (provider, _state) = mock(&oversize, None).await;
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert!(
		matches!(result, Err(ProviderError::Remote(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn mx_with_unparseable_priority_returns_unsupported() {
	let (provider, _state) = mock("", None).await;
	let bad = super::super::provider::DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "ten mail.example.org".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert("example.org", bad).await,
		Err(ProviderError::Unsupported)
	);
}

#[tokio::test]
async fn srv_with_wrong_field_count_returns_unsupported() {
	let (provider, _state) = mock("", None).await;
	let bad = super::super::provider::DnsRecord {
		name: "_sip._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "10 5 sip.example.org".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert("example.org", bad).await,
		Err(ProviderError::Unsupported)
	);
}

#[tokio::test]
async fn mx_with_missing_whitespace_returns_unsupported() {
	let (provider, _state) = mock("", None).await;
	let bad = super::super::provider::DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10mail.example.org".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert("example.org", bad).await,
		Err(ProviderError::Unsupported)
	);
}
