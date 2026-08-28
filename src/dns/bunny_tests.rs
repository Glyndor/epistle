//! Tests for the Bunny.net provider against an in-process axum mock of the
//! Bunny DNS API. The mock mirrors Bunny's endpoints:
//!
//! - `GET    /dnszone?search=...`         — list zones
//! - `GET    /dnszone/{id}`               — zone detail (includes records)
//! - `PUT    /dnszone/{id}/records`       — create record
//! - `POST   /dnszone/{id}/records/{rid}`  — update record
//! - `DELETE /dnszone/{id}/records/{rid}`  — delete record

use super::*;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::Uri;
use axum::routing::{get, post};
use axum::{Json, Router};

#[derive(Default)]
struct MockState {
	calls: Vec<String>,
	have_dmarc: bool,
	auth: Option<String>,
	bodies: Vec<String>,
	next_record_id: i64,
	zones: serde_json::Value,
	zone_detail: serde_json::Value,
}

type Shared = Arc<Mutex<MockState>>;

#[derive(serde::Deserialize, Default)]
struct SearchParams {
	#[serde(default)]
	#[allow(dead_code)]
	search: Option<String>,
}

async fn list_zones(
	State(state): State<Shared>,
	Query(params): Query<SearchParams>,
	uri: Uri,
) -> Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.calls.push(format!(
		"GET {}",
		uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
	));
	s.calls.last_mut().unwrap().push_str(" dnszone-search");
	let _ = params;
	Json(s.zones.clone())
}

async fn zone_detail(State(state): State<Shared>, uri: Uri) -> Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("GET {}", uri.path()));
	let detail = if s.have_dmarc {
		serde_json::json!({
			"Id": 42,
			"Records": [
				{ "Id": 1001, "Type": 3, "Name": "_dmarc", "Value": "old", "Ttl": 3600 }
			]
		})
	} else {
		s.zone_detail.clone()
	};
	Json(detail)
}

async fn add_record(
	State(state): State<Shared>,
	method: axum::http::Method,
	uri: Uri,
	headers: axum::http::HeaderMap,
	body: String,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} {}", uri.path()));
	s.auth = headers
		.get("accesskey")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	s.bodies.push(body);
	s.next_record_id += 1;
	let payload = serde_json::json!({
		"Id": s.next_record_id,
		"Type": 3,
		"Ttl": 3600,
		"Value": "",
		"Name": ""
	});
	(axum::http::StatusCode::CREATED, Json(payload))
}

async fn update_record(
	State(state): State<Shared>,
	method: axum::http::Method,
	uri: Uri,
	headers: axum::http::HeaderMap,
	body: String,
) -> axum::http::StatusCode {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} {}", uri.path()));
	s.auth = headers
		.get("accesskey")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	s.bodies.push(body);
	axum::http::StatusCode::NO_CONTENT
}

async fn delete_record(
	State(state): State<Shared>,
	method: axum::http::Method,
	uri: Uri,
) -> axum::http::StatusCode {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} {}", uri.path()));
	axum::http::StatusCode::NO_CONTENT
}

async fn mock() -> (BunnyProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		zones: serde_json::json!({
			"Items": [
				{ "Id": 42, "Domain": "example.org" }
			],
			"CurrentPage": 1,
			"TotalItems": 1,
			"HasMoreItems": false
		}),
		zone_detail: serde_json::json!({
			"Id": 42,
			"Records": []
		}),
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
		.with_base(format!("http://{addr}"));
	(provider, state)
}

#[tokio::test]
async fn smoke() {
	let _ = mock().await;
}
fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
}

#[tokio::test]
async fn upsert_subname_uses_access_key_and_relative_name() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.len(), 3);
	assert!(s.calls[0].starts_with("GET /dnszone?search=example.org"));
	assert_eq!(s.calls[1], "GET /dnszone/42");
	assert_eq!(s.calls[2], "PUT /dnszone/42/records");
	let body = &s.bodies[0];
	assert!(body.contains("\"Type\":3"), "{body}");
	assert!(body.contains("\"Name\":\"_dmarc\""), "{body}");
	assert!(body.contains("\"Value\":\"v=DMARC1; p=none\""), "{body}");
	assert!(body.contains("\"Ttl\":3600"), "{body}");
	assert_eq!(s.auth.as_deref(), Some("tok"));
}

#[tokio::test]
async fn upsert_at_apex_uses_empty_name() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("\"Name\":\"\""), "{body}");
}

#[tokio::test]
async fn upsert_updates_when_record_already_exists() {
	let (provider, state) = mock().await;
	state.lock().unwrap().have_dmarc = true;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "new"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.last().unwrap(), "POST /dnszone/42/records/1001");
	assert!(
		!s.calls.iter().any(|c| c.starts_with("PUT /dnszone")),
		"{:?}",
		s.calls
	);
}

#[tokio::test]
async fn upsert_twice_does_not_duplicate() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("first upsert");
	{
		let s = state.lock().unwrap();
		assert!(
			s.calls.iter().any(|c| c == "PUT /dnszone/42/records"),
			"{:?}",
			s.calls
		);
	}
	state.lock().unwrap().have_dmarc = true;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("second upsert");
	let s = state.lock().unwrap();
	let posts: Vec<_> = s
		.calls
		.iter()
		.filter(|c| c.starts_with("POST /dnszone/42/records/"))
		.collect();
	assert_eq!(posts.len(), 1, "{:?}", s.calls);
	let puts: Vec<_> = s
		.calls
		.iter()
		.filter(|c| c.starts_with("PUT /dnszone/42/records"))
		.collect();
	assert_eq!(puts.len(), 1, "{:?}", s.calls);
}

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
	state.lock().unwrap().have_dmarc = true;
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete present");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.last().unwrap(), "DELETE /dnszone/42/records/1001");
}

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
		.with_base(format!("http://{addr}"));
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
		.with_base(format!("http://{addr}"));
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1], "GET /dnszone/42");
}

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
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert("example.org", mx).await,
		Err(ProviderError::Unsupported)
	);
}
