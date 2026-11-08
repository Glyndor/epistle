use super::*;

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock(Vec::new()).await;
	let result = provider
		.upsert(ZONE, txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	let s = state.lock().unwrap();
	assert!(s.calls.is_empty(), "calls: {:?}", s.calls);
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, state) = mock(Vec::new()).await;
	let tlsa = DnsRecord {
		name: "_25._tcp.example.org".into(),
		kind: RecordKind::Tlsa,
		value: "3 0 1 abcd".into(),
		ttl: 3600,
		proxied: None,
	};
	assert_eq!(
		provider.upsert(ZONE, tlsa).await,
		Err(ProviderError::Unsupported)
	);
	assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn mx_upsert_splits_priority_target_into_fields() {
	let (provider, state) = mock(Vec::new()).await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert(ZONE, mx).await.expect("mx upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"content\":\"mail.example.org\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
}

#[tokio::test]
async fn srv_upsert_splits_priority_weight_port_target_into_fields() {
	let (provider, state) = mock(Vec::new()).await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert(ZONE, srv).await.expect("srv upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"content\":\"mail.example.org\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
}

#[tokio::test]
async fn caa_upsert_splits_into_content_flags_and_caa_tag() {
	let (provider, state) = mock(Vec::new()).await;
	let caa = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Caa,
		value: "0 issue \"letsencrypt.org\"".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert(ZONE, caa).await.expect("caa upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("\"type\":\"CAA\""), "{body}");
	assert!(body.contains("\"content\":\"letsencrypt.org\""), "{body}");
	assert!(body.contains("\"flags\":0"), "{body}");
	assert!(body.contains("\"caa_tag\":\"issue\""), "{body}");
}
