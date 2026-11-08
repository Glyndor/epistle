use super::*;

/// `delete` reads the current set first, then either PUTs the remainder
/// or DELETEs the whole set when nothing remains. The path is the
/// `(type, name)` tail. With an empty live set the remainder is empty, so
/// the implementation goes GET (returns []) → DELETE.
#[tokio::test]
async fn delete_reads_the_set_and_sends_delete_when_nothing_remains() {
	let (provider, state) = mock().await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.len(), 2);
	assert_eq!(s.calls[0].method, Method::GET);
	assert_eq!(s.calls[0].path, "/domains/example.org/records/TXT/_dmarc");
	assert_eq!(s.calls[1].method, Method::DELETE);
	assert_eq!(s.calls[1].path, "/domains/example.org/records/TXT/_dmarc");
}

/// A 403 from the API is mapped to a `Remote` error whose message names
/// the GoDaddy eligibility check, not the generic "authentication
/// failed" the other providers return for 403. The text is part of the
/// operator's fix path.
#[tokio::test]
async fn forbidden_response_carries_the_eligibility_message() {
	let state: Shared = Arc::new(Mutex::new(MockState {
		zone_records: serde_json::json!([]),
		fail_with: Some(403),
		..Default::default()
	}));
	let app = Router::new()
		.route(
			"/domains/example.org/records/{kind}/{name}",
			put(put_records)
				.delete(delete_records)
				.get(get_records_by_name),
		)
		.route(
			"/domains/example.org/records",
			get(get_records_zone)
				.put(put_records)
				.delete(delete_records),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = GodaddyProvider::new(
		"ak".to_string(),
		"sk".to_string(),
		"example.org".to_string(),
	)
	.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	let err = result.expect_err("403 must error");
	let ProviderError::Remote(text) = err else {
		panic!("expected Remote, got {err:?}");
	};
	assert!(
		text.contains("eligible"),
		"403 message must name the eligibility check: {text}"
	);
}

/// A 401 (bad key) maps to `ProviderError::Auth`. The provider does not
/// leak the key or the secret into the error message.
#[tokio::test]
async fn unauthorized_response_maps_to_auth_error() {
	let state: Shared = Arc::new(Mutex::new(MockState {
		zone_records: serde_json::json!([]),
		fail_with: Some(401),
		..Default::default()
	}));
	let app = Router::new()
		.route(
			"/domains/example.org/records/{kind}/{name}",
			put(put_records)
				.delete(delete_records)
				.get(get_records_by_name),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = GodaddyProvider::new(
		"ak".to_string(),
		"sk".to_string(),
		"example.org".to_string(),
	)
	.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	let result = provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
}

/// A record outside the configured zone is rejected before any network
/// call. The mock has no listener; if `authorize` did not fire, the
/// call would have to reach a peer.
#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock().await;
	let result = provider
		.upsert(
			"example.org",
			txt("_dmarc.other.example", "v=DMARC1; p=none"),
		)
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().calls.is_empty());
}
