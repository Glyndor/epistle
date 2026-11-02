use super::*;

/// The `Authorization` header MUST be `sso-key <api_key>:<api_secret>`, in
/// that order. A wrong order is the classic mistake, the test pins the
/// exact shape so a future change in `auth_header` cannot drift without
/// the test going red.
#[tokio::test]
async fn upsert_sends_sso_key_header_in_key_colon_secret_order() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.len(), 2, "GET then PUT");
	let call = &s.calls[1];
	assert_eq!(call.method, Method::PUT);
	assert_eq!(call.path, "/domains/example.org/records/TXT/_dmarc");
	assert_eq!(
		call.auth.as_deref(),
		Some("sso-key ak_under_test:sk_under_test_secret"),
		"key must precede secret in the sso-key header"
	);
}

/// The `PUT` body is a one-element JSON array with `data` and `ttl`. The
/// API replaces the whole record set at `(type, name)`, so a single
/// upsert sends one element and the array shape is the contract the
/// caller is pinning.
#[tokio::test]
async fn upsert_txt_sends_one_element_array_with_data_and_ttl() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().calls[1].body).expect("parse body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(arr.len(), 1, "one element per call");
	let element = &arr[0];
	assert_eq!(element["data"], "v=DMARC1; p=none");
	assert_eq!(element["ttl"], 3600);
	// MX/SRV must not bleed in.
	assert!(element.get("priority").is_none());
	assert!(element.get("weight").is_none());
}

/// The MX body carries `priority` and `data` (the target) on the array
/// element. The presentation form (`<prio> <target>`) is split out so
/// the wire payload matches the API.
#[tokio::test]
async fn upsert_mx_splits_priority_and_target() {
	let (provider, state) = mock().await;
	let mx = DnsRecord::new("example.org", RecordKind::Mx, "10 mail.example.org", 3600);
	provider.upsert("example.org", mx).await.expect("mx upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().calls[1].body).expect("parse");
	let arr = body.as_array().unwrap();
	assert_eq!(arr.len(), 1);
	assert_eq!(arr[0]["data"], "mail.example.org");
	assert_eq!(arr[0]["priority"], 10);
	assert_eq!(arr[0]["ttl"], 3600);
}

/// The SRV body carries the dedicated `priority`/`weight`/`port`/`service`/
/// `protocol` fields the API requires, plus the target under both
/// `data` and `host`. `data` is the string the API expects (not a
/// JSON object); the service and protocol come from the owner name
/// (`_submissions._tcp.example.org` -> `_submissions`, `_tcp`). A
/// payload with a JSON-object `data` and empty `service`/`protocol`
/// is what the previous code sent; the API rejects that shape.
#[tokio::test]
async fn upsert_srv_uses_string_data_with_service_and_protocol_from_owner() {
	let (provider, state) = mock().await;
	let srv = DnsRecord::new(
		"_submissions._tcp.example.org",
		RecordKind::Srv,
		"0 1 465 mail.example.org",
		3600,
	);
	provider
		.upsert("example.org", srv)
		.await
		.expect("srv upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().calls[1].body).expect("parse");
	let arr = body.as_array().unwrap();
	assert_eq!(arr.len(), 1);
	let element = &arr[0];
	assert_eq!(
		element["data"], "mail.example.org",
		"data is the target string, not a JSON object"
	);
	assert_eq!(element["priority"], 0);
	assert_eq!(element["weight"], 1);
	assert_eq!(element["port"], 465);
	assert_eq!(element["service"], "_submissions");
	assert_eq!(element["protocol"], "_tcp");
	assert_eq!(element["host"], "mail.example.org");
}

/// A TTL below the API floor (600) is raised to the floor before the
/// request goes out. The test pins the value at 600, without the
/// raise, the request would carry the original 300 and GoDaddy would
/// reject it.
#[tokio::test]
async fn low_ttl_is_raised_to_the_minimum() {
	let (provider, state) = mock().await;
	provider
		.upsert(
			"example.org",
			DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 mx -all", 300),
		)
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().calls[1].body).expect("parse");
	assert_eq!(body[0]["ttl"], 600);
}

/// Upsert at the zone apex uses the literal `@` GoDaddy requires.
#[tokio::test]
async fn upsert_at_apex_uses_at_for_relative_name() {
	let (provider, state) = mock().await;
	provider
		.upsert(
			"example.org",
			DnsRecord::new("example.org", RecordKind::A, "203.0.113.10", 600),
		)
		.await
		.expect("apex upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1].path, "/domains/example.org/records/A/@");
}
