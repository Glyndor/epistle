//! Tests for the GoDaddy provider, against an in-process axum mock of the
//! v1 REST API.
//!
//! The mock answers with the JSON shapes documented at
//! <https://developer.godaddy.com/doc/endpoints/dns>: `PUT`/`DELETE`
//! endpoints are 200/204, `GET /domains/{zone}/records/{type}/{name}` returns
//! a JSON array of records, and `GET /domains/{zone}/records` returns the
//! full zone list. Every request carries an `Authorization: sso-key …` header.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, Method};
use axum::response::IntoResponse;
use axum::routing::{get, put};

use super::*;

/// One captured request: the method, the path it hit, the body it carried,
/// and the `Authorization` header it sent. The full set is kept in a `Vec`
/// so a test can assert the call order.
#[derive(Clone)]
pub(super) struct Call {
	pub(super) method: Method,
	pub(super) path: String,
	pub(super) body: String,
	pub(super) auth: Option<String>,
}

#[derive(Default)]
pub(super) struct MockState {
	/// Records the `GET /domains/{zone}/records` endpoint returns. The
	/// full zone list, used for `list`.
	pub(super) zone_records: serde_json::Value,
	/// Per-`(kind, name)` record sets. Populated by PUT, cleared by
	/// DELETE, returned by GET. Tests pre-populate it to simulate an
	/// existing set; the GET handler returns an empty array for an
	/// absent key so a fresh zone reads as `[]`.
	pub(super) per_name_records: std::collections::HashMap<(String, String), serde_json::Value>,
	/// Every request seen, in order.
	pub(super) calls: Vec<Call>,
	/// When set, every endpoint answers this status code with an empty body.
	pub(super) fail_with: Option<u16>,
}

pub(super) type Shared = Arc<Mutex<MockState>>;

async fn put_records(
	State(state): State<Shared>,
	method: Method,
	uri: axum::http::Uri,
	headers: HeaderMap,
	body: String,
) -> axum::response::Response {
	if let Some(resp) = fail_response(&state) {
		return resp;
	}
	let path = uri.path().to_string();
	record(&state, method.clone(), &path, headers, body.clone());
	if method == Method::PUT
		&& let Some(key) = parse_per_name(&path)
		&& let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
	{
		state.lock().unwrap().per_name_records.insert(key, json);
	}
	axum::response::Response::builder()
		.status(axum::http::StatusCode::OK)
		.body(axum::body::Body::empty())
		.unwrap()
}

async fn delete_records(
	State(state): State<Shared>,
	method: Method,
	uri: axum::http::Uri,
	headers: HeaderMap,
) -> axum::response::Response {
	if let Some(resp) = fail_response(&state) {
		return resp;
	}
	let path = uri.path().to_string();
	record(&state, method, &path, headers, String::new());
	if let Some(key) = parse_per_name(&path) {
		state.lock().unwrap().per_name_records.remove(&key);
	}
	axum::response::Response::builder()
		.status(axum::http::StatusCode::NO_CONTENT)
		.body(axum::body::Body::empty())
		.unwrap()
}

async fn get_records_by_name(
	State(state): State<Shared>,
	method: Method,
	uri: axum::http::Uri,
	headers: HeaderMap,
) -> axum::response::Response {
	if let Some(resp) = fail_response(&state) {
		return resp;
	}
	record(&state, method, uri.path(), headers, String::new());
	let key = parse_per_name(uri.path());
	let stored = key
		.and_then(|k| state.lock().unwrap().per_name_records.get(&k).cloned())
		.unwrap_or_else(|| serde_json::json!([]));
	axum::Json(stored).into_response()
}

async fn get_records_zone(
	State(state): State<Shared>,
	method: Method,
	uri: axum::http::Uri,
	headers: HeaderMap,
) -> axum::response::Response {
	if let Some(resp) = fail_response(&state) {
		return resp;
	}
	record(&state, method, uri.path(), headers, String::new());
	let records = state.lock().unwrap().zone_records.clone();
	axum::Json(records).into_response()
}

/// When `fail_with` is set, return a response with that status code. The
/// handler does not call `record` on the failure path, so the request is
/// not captured; the test only asserts on the error mapping, not on
/// what the request looked like.
fn fail_response(state: &Shared) -> Option<axum::response::Response> {
	let code = state.lock().unwrap().fail_with?;
	let status = axum::http::StatusCode::from_u16(code).ok()?;
	Some(
		axum::response::Response::builder()
			.status(status)
			.body(axum::body::Body::empty())
			.unwrap(),
	)
}

fn record(state: &Shared, method: Method, path: &str, headers: HeaderMap, body: String) {
	state.lock().unwrap().calls.push(Call {
		method,
		path: path.to_string(),
		body,
		auth: headers
			.get("authorization")
			.and_then(|v| v.to_str().ok())
			.map(str::to_string),
	});
}

/// Extract the `(kind, name)` pair from a per-name path of the shape
/// `/domains/{zone}/records/{kind}/{name}`. The zone-wide
/// `/domains/{zone}/records` path returns `None`. Used by the GET/PUT/
/// DELETE handlers to look up the per-name record set.
pub(super) fn parse_per_name(path: &str) -> Option<(String, String)> {
	let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
	if parts.len() == 5 && parts[0] == "domains" && parts[2] == "records" {
		Some((parts[3].to_string(), parts[4].to_string()))
	} else {
		None
	}
}

/// Start the mock and return (provider pointed at it, shared state).
pub(super) async fn mock() -> (GodaddyProvider, Shared) {
	mock_with(serde_json::json!([])).await
}

pub(super) async fn mock_with(zone_records: serde_json::Value) -> (GodaddyProvider, Shared) {
	mock_with_per_name(zone_records, Default::default()).await
}

pub(super) async fn mock_with_per_name(
	zone_records: serde_json::Value,
	per_name_records: std::collections::HashMap<(String, String), serde_json::Value>,
) -> (GodaddyProvider, Shared) {
	let (base, state) = mock_with_per_name_raw(zone_records, per_name_records).await;
	let provider = GodaddyProvider::new(
		"ak_under_test".to_string(),
		"sk_under_test_secret".to_string(),
		"example.org".to_string(),
	)
	.with_base(base);
	(provider, state)
}

/// Start the mock and return `(base_url, shared_state)`. The caller
/// builds the provider so a test can configure a non-default zone
/// (the trailing-dot case, for example) and still point at the same
/// mock the other tests use.
pub(super) async fn mock_with_per_name_raw(
	zone_records: serde_json::Value,
	per_name_records: std::collections::HashMap<(String, String), serde_json::Value>,
) -> (String, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		zone_records,
		per_name_records,
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
	(format!("http://{addr}"), state)
}

pub(super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
}

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
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
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
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
	};
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
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Txt,
				value: "v=spf1 mx -all".into(),
				ttl: 300,
			},
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
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::A,
				value: "203.0.113.10".into(),
				ttl: 600,
			},
		)
		.await
		.expect("apex upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1].path, "/domains/example.org/records/A/@");
}

/// Authorisation is case-insensitive on the zone and the owner name;
/// the FQDN-to-relative conversion has to follow the same rule or
/// `_dmarc.EXAMPLE.ORG` reaches the API as a full owner and the
/// apex absolute name `EXAMPLE.ORG` lands on the wrong path. Both
/// paths must agree, otherwise a DMARC publish with mixed case
/// either 401s (wrong path) or 404s (no such record set).
#[tokio::test]
async fn fqdn_to_relative_is_case_insensitive_on_the_zone_suffix() {
	let (provider, state) = mock().await;
	// Apex in upper case.
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "EXAMPLE.ORG".into(),
				kind: RecordKind::A,
				value: "203.0.113.10".into(),
				ttl: 600,
			},
		)
		.await
		.expect("apex upsert");
	// Sub-name in mixed case; the prefix is preserved, only the
	// zone suffix is matched case-insensitively.
	provider
		.upsert("example.org", txt("_DMARC.Example.Org", "v=DMARC1"))
		.await
		.expect("sub upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1].path, "/domains/example.org/records/A/@");
	assert_eq!(s.calls[3].path, "/domains/example.org/records/TXT/_DMARC");
}

/// `list` reads the zone-wide endpoint, not the per-name one. The
/// relative names GoDaddy returns (`@`, `_dmarc`) are joined back to
/// FQDNs the rest of epistle expects.
#[tokio::test]
async fn list_parses_zone_records_and_emits_fqdn_names() {
	let zone_records = serde_json::json!([
		serde_json::json!({"type": "A", "name": "@", "data": "203.0.113.10", "ttl": 600}),
		serde_json::json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1; p=none", "ttl": 600}),
		serde_json::json!({"type": "MX", "name": "@", "data": "mail.example.org.", "ttl": 600, "priority": 10}),
		serde_json::json!({"type": "SRV", "name": "_submissions._tcp", "data": "mail.example.org.", "ttl": 600, "priority": 0, "weight": 1, "port": 465}),
	]);
	let (provider, _state) = mock_with(zone_records).await;
	let listed = provider.list("example.org").await.expect("list");
	let apex = listed
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.kind, RecordKind::A);
	assert_eq!(apex.value, "203.0.113.10");
	let dmarc = listed
		.iter()
		.find(|r| r.name == "_dmarc.example.org")
		.expect("dmarc");
	assert_eq!(dmarc.kind, RecordKind::Txt);
	assert_eq!(dmarc.value, "v=DMARC1; p=none");
	let mx = listed
		.iter()
		.find(|r| r.name == "example.org" && r.kind == RecordKind::Mx)
		.expect("mx");
	assert_eq!(mx.value, "10 mail.example.org");
	let srv = listed
		.iter()
		.find(|r| r.kind == RecordKind::Srv)
		.expect("srv");
	assert_eq!(srv.value, "0 1 465 mail.example.org");
}

/// GoDaddy returns names relative to the zone, always. A returned
/// name that happens to contain the zone suffix is still a
/// legitimate relative label, not an absolute FQDN. The previous
/// code's "ends with .zone" guess would resolve `mail.example.org`
/// as `mail.example.org` (the absolute name) when the API meant
/// `mail.example.org.example.org`. Round-tripping that record
/// through `delete` would then target `/records/{type}/mail`,
/// a different owner.
#[tokio::test]
async fn list_never_guesses_whether_a_returned_name_is_absolute() {
	let zone_records = serde_json::json!([
		// The API returned this name as a relative label; the
		// concatenation is the contract.
		serde_json::json!({"type": "A", "name": "mail.example.org", "data": "203.0.113.10", "ttl": 600}),
	]);
	let (provider, _state) = mock_with(zone_records).await;
	let listed = provider.list("example.org").await.expect("list");
	assert_eq!(listed.len(), 1);
	assert_eq!(
		listed[0].name, "mail.example.org.example.org",
		"a relative name is always joined to the zone, regardless of suffix"
	);
}

/// Apex NS, SOA, and other kinds the provider does not publish
/// appear in the zone. The previous code mapped every unknown
/// type to TXT, so a list call would return an apex TXT-shaped
/// record for the NS or SOA entries; round-tripping that record
/// through `upsert` or `delete` would then operate on the apex
/// TXT set, not on the original record type.
#[tokio::test]
async fn list_skips_records_of_unsupported_kinds() {
	let zone_records = serde_json::json!([
		serde_json::json!({"type": "NS", "name": "@", "data": "ns1.example.org.", "ttl": 600}),
		serde_json::json!({"type": "SOA", "name": "@", "data": "ns1.example.org. admin.example.org. 1 7200 3600 1209600 3600", "ttl": 600}),
		serde_json::json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1", "ttl": 600}),
	]);
	let (provider, _state) = mock_with(zone_records).await;
	let listed = provider.list("example.org").await.expect("list");
	assert_eq!(
		listed.len(),
		1,
		"only the TXT record is published by this provider"
	);
	assert_eq!(listed[0].kind, RecordKind::Txt);
	assert_eq!(listed[0].value, "v=DMARC1");
}

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
	.with_base(format!("http://{addr}"));
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
	.with_base(format!("http://{addr}"));
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
