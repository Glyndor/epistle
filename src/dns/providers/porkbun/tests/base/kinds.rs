use super::*;

#[tokio::test]
async fn record_outside_the_zone_is_rejected_without_network() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let result = provider
		.upsert(
			"example.org",
			txt("_dmarc.other.example", "v=DMARC1; p=none"),
		)
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn mx_upsert_splits_priority_and_target() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state.lock().unwrap().body("/dns/create/example.org");
	assert_eq!(body["type"], "MX");
	assert_eq!(body["content"], "mail.example.org");
	assert_eq!(body["prio"], serde_json::json!(10));
}

#[tokio::test]
async fn srv_upsert_passes_value_through_and_sets_prio_to_priority() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", srv).await.expect("upsert");
	let body = state.lock().unwrap().body("/dns/create/example.org");
	assert_eq!(body["type"], "SRV");
	assert_eq!(body["name"], "_submissions._tcp");
	// Porkbun's SRV `content` field carries the full value verbatim; the
	// `prio` field is the plain preference (here, the priority — weight and
	// port are part of the value).
	assert_eq!(body["content"], "0 1 465 mail.example.org");
	assert_eq!(body["prio"], serde_json::json!(0));
}
