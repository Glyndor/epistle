//! Tests for the Spaceship provider against an in-process axum mock of
//! <https://spaceship.dev/api/v1/dns/records/{domain}>.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use serde::Deserialize;

#[derive(Default)]
struct MockState {
	/// Records the GET endpoint returns. Keyed by `kind|name` so PUT/DELETE
	/// lookups can match an "existing" record without filtering the list.
	records: std::collections::HashMap<String, serde_json::Value>,
	/// Captured PUT/DELETE bodies.
	bodies: Vec<String>,
	/// "METHOD /path?query" of every request, for assertions.
	calls: Vec<String>,
	/// X-API-Key header seen on the last request.
	api_key: Option<String>,
	/// X-API-Secret header seen on the last request.
	api_secret: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

/// Query parameters the mock accepts — Spaceship requires `take` and `skip`,
/// and may carry `orderBy`.
#[derive(Deserialize)]
struct ListQuery {
	#[serde(default)]
	take: Option<i64>,
	#[serde(default)]
	skip: Option<i64>,
}

/// Record the call against the shared mock state. Called from every method
/// handler so the auth-headers and the captured call list stay in sync.
fn record_call(
	state: &Shared,
	method: axum::http::Method,
	headers: &axum::http::HeaderMap,
	zone: &str,
	query: &ListQuery,
) {
	let mut s = state.lock().unwrap();
	s.api_key = headers
		.get("x-api-key")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	s.api_secret = headers
		.get("x-api-secret")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	let path = match (&query.take, &query.skip) {
		(Some(t), Some(sk)) => format!("/dns/records/{zone}?take={t}&skip={sk}"),
		_ => format!("/dns/records/{zone}"),
	};
	s.calls.push(format!("{method} {path}"));
}

/// `GET /dns/records/{zone}` — list records.
async fn list_records(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
	Path(zone): Path<String>,
	Query(query): Query<ListQuery>,
) -> axum::Json<serde_json::Value> {
	record_call(&state, axum::http::Method::GET, &headers, &zone, &query);
	let s = state.lock().unwrap();
	let items: Vec<serde_json::Value> = s.records.values().cloned().collect();
	let total = items.len() as i64;
	axum::Json(serde_json::json!({"items": items, "total": total}))
}

/// `PUT /dns/records/{zone}` — append items with `force: true`.
async fn save_records(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
	Path(zone): Path<String>,
	Query(query): Query<ListQuery>,
	body: String,
) -> axum::http::StatusCode {
	record_call(&state, axum::http::Method::PUT, &headers, &zone, &query);
	let mut s = state.lock().unwrap();
	s.bodies.push(body.clone());
	// Decode and store, mimicking Spaceship's overwrite-under-force:true.
	if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body)
		&& let Some(items) = parsed.get("items").and_then(|v| v.as_array())
	{
		for item in items {
			if let (Some(k), Some(n)) = (
				item.get("type").and_then(|v| v.as_str()),
				item.get("name").and_then(|v| v.as_str()),
			) {
				s.records.insert(format!("{k}|{n}"), item.clone());
			}
		}
	}
	axum::http::StatusCode::NO_CONTENT
}

/// `DELETE /dns/records/{zone}` — remove items.
async fn delete_records(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
	Path(zone): Path<String>,
	Query(query): Query<ListQuery>,
	body: String,
) -> axum::http::StatusCode {
	record_call(&state, axum::http::Method::DELETE, &headers, &zone, &query);
	let mut s = state.lock().unwrap();
	s.bodies.push(body.clone());
	// Each entry is a `(type, name)` we should remove. TXT delete items
	// may also carry `value`, which we ignore for matching (we key by
	// `type|name`).
	if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
		for item in items {
			if let (Some(k), Some(n)) = (
				item.get("type").and_then(|v| v.as_str()),
				item.get("name").and_then(|v| v.as_str()),
			) {
				s.records.remove(&format!("{k}|{n}"));
			}
		}
	}
	axum::http::StatusCode::NO_CONTENT
}

async fn mock(records: Vec<serde_json::Value>) -> (SpaceshipProvider, Shared) {
	let mut map = std::collections::HashMap::new();
	for r in records {
		let key = format!(
			"{}|{}",
			r.get("type").and_then(|v| v.as_str()).unwrap_or(""),
			r.get("name").and_then(|v| v.as_str()).unwrap_or(""),
		);
		map.insert(key, r);
	}
	let state: Shared = Arc::new(Mutex::new(MockState {
		records: map,
		..Default::default()
	}));
	let app = Router::new()
		.route(
			"/dns/records/{zone}",
			get(list_records).put(save_records).delete(delete_records),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = SpaceshipProvider::new("AK".into(), "SK".into(), "example.org".into())
		.with_base(format!("http://{addr}"));
	(provider, state)
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
async fn upsert_txt_under_subdomain_sends_relative_name_and_two_auth_headers() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	// DELETE first (Spaceship has no in-place update), then PUT.
	let delete = s
		.calls
		.iter()
		.find(|c| c.starts_with("DELETE /dns/records/example.org"))
		.expect("DELETE");
	assert!(delete.contains("?take=") || delete.contains("DELETE /dns/records/example.org"));
	let put = s
		.calls
		.iter()
		.find(|c| c.starts_with("PUT /dns/records/example.org"))
		.expect("PUT");
	assert!(put.contains("?take=") || put.contains("PUT /dns/records/example.org"));
	// DELETE body — TXT needs the value.
	let delete_body = s
		.bodies
		.iter()
		.find(|b| b.contains("\"DELETE\"") || b.starts_with('['))
		.expect("delete body");
	assert!(delete_body.contains("\"type\":\"TXT\""), "{delete_body}");
	assert!(delete_body.contains("\"name\":\"_dmarc\""), "{delete_body}");
	assert!(delete_body.contains("v=DMARC1; p=none"), "{delete_body}");
	// PUT body — `force: true`, value under `value` (not `address`).
	let put_body = s
		.bodies
		.iter()
		.find(|b| b.contains("\"force\""))
		.expect("put body");
	assert!(put_body.contains("\"force\":true"), "{put_body}");
	assert!(put_body.contains("\"type\":\"TXT\""), "{put_body}");
	assert!(put_body.contains("\"name\":\"_dmarc\""), "{put_body}");
	assert!(put_body.contains("\"ttl\":3600"), "{put_body}");
	assert!(
		put_body.contains("\"value\":\"v=DMARC1; p=none\""),
		"{put_body}"
	);
	// Auth: two separate headers, exactly as Spaceship documents.
	assert_eq!(s.api_key.as_deref(), Some("AK"));
	assert_eq!(s.api_secret.as_deref(), Some("SK"));
}

#[tokio::test]
async fn upsert_at_apex_uses_at_for_relative_name() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let put_body = state
		.lock()
		.unwrap()
		.bodies
		.iter()
		.find(|b| b.contains("\"force\""))
		.unwrap()
		.clone();
	assert!(put_body.contains("\"name\":\"@\""), "{put_body}");
}

#[tokio::test]
async fn upsert_when_record_exists_replaces_via_delete_then_put() {
	let existing = vec![serde_json::json!({
		"type": "TXT", "name": "_dmarc", "ttl": 1800, "value": "v=DMARC1; p=none"
	})];
	let (provider, state) = mock(existing).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let delete_count = s.calls.iter().filter(|c| c.starts_with("DELETE")).count();
	let put_count = s.calls.iter().filter(|c| c.starts_with("PUT")).count();
	assert_eq!(delete_count, 1, "calls: {:?}", s.calls);
	assert_eq!(put_count, 1, "calls: {:?}", s.calls);
	// Final body carries the new value, not the old one.
	let final_body = s.bodies.last().expect("body");
	assert!(
		final_body.contains("\"value\":\"v=DMARC1; p=reject\""),
		"{final_body}"
	);
}

#[tokio::test]
async fn delete_is_idempotent_when_record_absent() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("delete absent is Ok");
	let s = state.lock().unwrap();
	// DELETE happened (idempotent at the API layer: 204 either way), no GET
	// or PUT was made.
	assert!(
		s.calls.iter().filter(|c| c.starts_with("DELETE")).count() == 1,
		"calls: {:?}",
		s.calls
	);
	assert!(
		!s.calls.iter().any(|c| c.starts_with("PUT")),
		"calls: {:?}",
		s.calls
	);
}

#[tokio::test]
async fn list_parses_real_response_and_emits_fqdn_names() {
	let records = vec![
		serde_json::json!({
			"type": "TXT", "name": "@", "ttl": 3600, "value": "v=spf1 -all",
			"group": {"type": "custom"}
		}),
		serde_json::json!({
			"type": "TXT", "name": "_dmarc", "ttl": 3600, "value": "v=DMARC1; p=none",
			"group": {"type": "custom"}
		}),
		serde_json::json!({
			"type": "A", "name": "mail", "ttl": 3600, "address": "203.0.113.10",
			"group": {"type": "custom"}
		}),
	];
	let (provider, _state) = mock(records).await;
	let listed = provider.list("example.org").await.expect("list");
	let apex = listed
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex TXT");
	assert_eq!(apex.value, "v=spf1 -all");
	assert_eq!(apex.ttl, 3600);
	let dmarc = listed
		.iter()
		.find(|r| r.name == "_dmarc.example.org")
		.expect("dmarc");
	assert_eq!(dmarc.value, "v=DMARC1; p=none");
	// A record: name "mail" → "mail.example.org", value comes from `address`.
	let mail_a = listed
		.iter()
		.find(|r| r.name == "mail.example.org")
		.expect("mail A");
	assert_eq!(mail_a.value, "203.0.113.10");
	assert_eq!(mail_a.kind, RecordKind::A);
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock(Vec::new()).await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	let s = state.lock().unwrap();
	assert!(s.calls.is_empty(), "no API calls: {:?}", s.calls);
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, _state) = mock(Vec::new()).await;
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

#[tokio::test]
async fn srv_upsert_splits_into_priority_weight_port_target() {
	let (provider, state) = mock(Vec::new()).await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", srv).await.expect("upsert");
	// Spaceship upserts as `remove then add`; the PUT body is the last one.
	let body = state.lock().unwrap().bodies.last().cloned().unwrap();
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"target\":\"mail.example.org\""), "{body}");
}
