use super::*;

#[tokio::test]
async fn list_parses_records_with_fqdn_names() {
	let detail = serde_json::json!({
		"Id": 42,
		"Records": [
			{ "Id": 1, "Type": 3, "Name": "", "Value": "v=spf1 -all", "Ttl": 3600 },
			{ "Id": 2, "Type": 3, "Name": "_dmarc", "Value": "v=DMARC1; p=none", "Ttl": 3600 }
		]
	});
	let state: Shared = Arc::new(Mutex::new(MockState {
		zones: serde_json::json!({"Items":[{"Id":42,"Domain":"example.org"}]}),
		zone_detail: detail,
		next_record_id: 1000,
		..Default::default()
	}));
	let app = Router::new()
		.route("/dnszone", get(list_zones))
		.route("/dnszone/{zone_id}", get(zone_detail))
		.route(
			"/dnszone/{zone_id}/records",
			get(list_zones).put(add_record),
		)
		.route(
			"/dnszone/{zone_id}/records/{record_id}",
			post(update_record).delete(delete_record),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = BunnyProvider::new(ScopedSecret::new("example.org", "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 2);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.kind, RecordKind::Txt);
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(
		records
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.value == "v=DMARC1; p=none"),
		"{:?}",
		records
	);
}

#[tokio::test]
async fn zone_search_picks_exact_match_among_prefix_overlaps() {
	let zones = serde_json::json!({
		"Items": [
			{ "Id": 100, "Domain": "evilexample.org" },
			{ "Id": 42,  "Domain": "example.org" },
			{ "Id": 200, "Domain": "example.org.evil.test" }
		],
		"CurrentPage": 1,
		"TotalItems": 3,
		"HasMoreItems": false
	});
	let state: Shared = Arc::new(Mutex::new(MockState {
		zones,
		zone_detail: serde_json::json!({"Id": 42, "Records": []}),
		next_record_id: 1000,
		..Default::default()
	}));
	let app = Router::new()
		.route("/dnszone", get(list_zones))
		.route("/dnszone/{zone_id}", get(zone_detail))
		.route(
			"/dnszone/{zone_id}/records",
			get(list_zones).put(add_record),
		)
		.route(
			"/dnszone/{zone_id}/records/{record_id}",
			post(update_record).delete(delete_record),
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
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1], "GET /dnszone/42");
}
