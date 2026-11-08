use super::*;

#[tokio::test]
async fn delete_is_idempotent_when_record_absent() {
	let (provider, state) = mock().await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete absent");
	let s = state.lock().unwrap();
	assert!(
		!s.calls.iter().any(|c| c.starts_with("DELETE")),
		"{:?}",
		s.calls
	);
}

#[tokio::test]
async fn delete_calls_api_when_record_present() {
	let (provider, state) = mock().await;
	// Seed the mock with a TXT record whose value matches what the
	// test will delete (the value-bearing path drops only the
	// matching record).
	state.lock().unwrap().zone_detail = serde_json::json!({
		"Id": 42,
		"Records": [
			{ "Id": 1001, "Type": 3, "Name": "_dmarc", "Value": "v=DMARC1; p=none", "Ttl": 3600 }
		]
	});
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("delete present");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.last().unwrap(), "DELETE /dnszone/42/records/1001");
}

/// A TXT delete with a value must drop only the matching record and
/// leave siblings at the same owner. Two ACME DNS-01 challenges
/// at the same owner is the canonical case: cleaning up one
/// certificate order's challenge must not wipe the second
/// order's. Bunny addresses every record by id, so the fix is to
/// find the id whose value matches the value (not the first by
/// (type, name)) and delete that one alone. The records below
/// intentionally put the sibling first, so a regression that
/// returns the first record by type+name deletes the wrong id.
#[tokio::test]
async fn txt_delete_with_a_value_drops_only_the_matching_challenge() {
	let detail = serde_json::json!({
		"Id": 42,
		"Records": [
			{ "Id": 2002, "Type": 3, "Name": "_acme-challenge", "Value": "token-bbbb", "Ttl": 60 },
			{ "Id": 2001, "Type": 3, "Name": "_acme-challenge", "Value": "token-aaaa", "Ttl": 60 },
		]
	});
	let state: Shared = Arc::new(Mutex::new(MockState {
		zones: serde_json::json!({"Items":[{"Id":42,"Domain":"example.org"}]}),
		zone_detail: detail,
		..Default::default()
	}));
	let app = Router::new()
		.route("/dnszone", get(list_zones))
		.route("/dnszone/{id}", get(zone_detail))
		.route(
			"/dnszone/{id}/records",
			axum::routing::put(add_record).post(update_record),
		)
		.route(
			"/dnszone/{id}/records/{rid}",
			axum::routing::delete(delete_record),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = BunnyProvider::new(ScopedSecret::new("example.org", "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let s = state.lock().unwrap();
	assert_eq!(
		s.calls.last().unwrap(),
		"DELETE /dnszone/42/records/2001",
		"the matching id is deleted, not the sibling: {:?}",
		s.calls
	);
	assert!(
		!s.calls
			.iter()
			.any(|c| c == "DELETE /dnszone/42/records/2002"),
		"sibling id must not be deleted: {:?}",
		s.calls
	);
}
