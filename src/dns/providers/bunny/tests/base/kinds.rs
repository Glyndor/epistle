use super::*;

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock().await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, _state) = mock().await;
	// Bunny's API has no field for TLSA's usage/selector/matching tuple or
	// for CAA's flags/tag/value; both stay Unsupported (MX now works).
	let tlsa = DnsRecord {
		name: "_25._tcp.example.org".into(),
		kind: RecordKind::Tlsa,
		value: "3 0 1 abcd".into(),
		ttl: 3600,
		proxied: None,
	};
	assert_eq!(
		provider.upsert("example.org", tlsa).await,
		Err(ProviderError::Unsupported)
	);
}

#[tokio::test]
async fn mx_upsert_puts_priority_target_in_value() {
	let (provider, state) = mock().await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	// Bunny's Type 4 (MX) keeps the `<priority> <target>` shape in `Value`.
	assert!(body.contains("\"Type\":4"), "{body}");
	assert!(body.contains("\"Value\":\"10 mail.example.org\""), "{body}");
}

#[tokio::test]
async fn srv_upsert_puts_weight_port_target_in_value() {
	let (provider, state) = mock().await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", srv).await.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	// Bunny's Type 8 (SRV) carries `weight port target` in Value (priority
	// is fixed at 0 by the Bunny API).
	assert!(body.contains("\"Type\":8"), "{body}");
	assert!(
		body.contains("\"Value\":\"1 465 mail.example.org\""),
		"{body}"
	);
}
