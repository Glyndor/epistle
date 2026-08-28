//! Tests for the DNSimple provider, against an in-process axum mock of the
//! `/v2/{account}/zones/{zone}/records` API. The mock captures the
//! `Authorization` header, every request method/path, and the bodies of
//! `POST`/`PATCH` so each test can assert against the exact wire shape.

use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;

#[derive(Default)]
struct MockState {
	/// Records the `GET` endpoint returns. Mutated by `POST`/`PATCH`/`DELETE`
	/// so subsequent `GET`s reflect changes.
	records: Vec<serde_json::Value>,
	/// Next id the mock assigns to a created record.
	next_id: u64,
	/// Captured "METHOD /path" of every request, in order.
	calls: Vec<String>,
	/// Captured `POST`/`PATCH` bodies, in order.
	bodies: Vec<String>,
	/// Last `Authorization` header seen (set on every request).
	auth: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

const ACCOUNT: &str = "1";
const ZONE: &str = "example.org";
const PATH_BASE: &str = "/v2/{account}/zones/{zone}/records";
const PATH_ITEM: &str = "/v2/{account}/zones/{zone}/records/{id}";

fn record(id: u64, name: &str, kind: &str, content: &str, ttl: u32) -> serde_json::Value {
	serde_json::json!({
		"id": id,
		"zone_id": ZONE,
		"parent_id": null,
		"name": name,
		"content": content,
		"ttl": ttl,
		"priority": null,
		"type": kind,
		"regions": ["global"],
		"system_record": false,
	})
}

fn json_response(status: u16, body: &str) -> axum::http::Response<String> {
	let status = StatusCode::from_u16(status).expect("status");
	axum::http::Response::builder()
		.status(status)
		.header(axum::http::header::CONTENT_TYPE, "application/json")
		.body(body.to_string())
		.expect("build response")
}

fn note_auth(state: &Shared, headers: &axum::http::HeaderMap) {
	state.lock().unwrap().auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
}

async fn list_records(
	State(state): State<Shared>,
	Path((account, zone)): Path<(String, String)>,
	Query(params): Query<HashMap<String, String>>,
	headers: axum::http::HeaderMap,
) -> axum::http::Response<String> {
	assert_eq!(account, ACCOUNT, "wrong account in path");
	assert_eq!(zone, ZONE, "wrong zone in path");
	note_auth(&state, &headers);
	let mut s = state.lock().unwrap();
	s.calls.push(format!("GET {PATH_BASE}"));
	let page: u32 = params.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
	let per_page: u32 = params
		.get("per_page")
		.and_then(|v| v.parse().ok())
		.unwrap_or(30);
	let total = s.records.len() as u32;
	let total_pages = if total == 0 {
		1
	} else {
		total.div_ceil(per_page)
	};
	let start = ((page - 1) * per_page) as usize;
	let end = (start + per_page as usize).min(total as usize);
	let page_data = if start < total as usize {
		s.records[start..end].to_vec()
	} else {
		Vec::new()
	};
	json_response(
		200,
		&serde_json::json!({
			"data": page_data,
			"pagination": {
				"current_page": page,
				"per_page": per_page,
				"total_entries": total,
				"total_pages": total_pages,
			}
		})
		.to_string(),
	)
}

async fn create_record(
	State(state): State<Shared>,
	Path((account, zone)): Path<(String, String)>,
	headers: axum::http::HeaderMap,
	body: String,
) -> axum::http::Response<String> {
	assert_eq!(account, ACCOUNT, "wrong account in path");
	assert_eq!(zone, ZONE, "wrong zone in path");
	note_auth(&state, &headers);
	let mut s = state.lock().unwrap();
	s.calls.push(format!("POST {PATH_BASE}"));
	s.bodies.push(body.clone());
	let payload: serde_json::Value = serde_json::from_str(&body).expect("parse posted record");
	s.next_id += 1;
	let id = s.next_id;
	let mut created = payload;
	created["id"] = serde_json::json!(id);
	created["zone_id"] = serde_json::json!(ZONE);
	s.records.push(created.clone());
	json_response(201, &serde_json::json!({ "data": created }).to_string())
}

async fn update_record(
	State(state): State<Shared>,
	Path((account, zone, id)): Path<(String, String, String)>,
	headers: axum::http::HeaderMap,
	body: String,
) -> axum::http::Response<String> {
	assert_eq!(account, ACCOUNT, "wrong account in path");
	assert_eq!(zone, ZONE, "wrong zone in path");
	assert!(!id.is_empty(), "empty record id");
	note_auth(&state, &headers);
	let mut s = state.lock().unwrap();
	s.calls.push(format!("PATCH {PATH_BASE}/{id}"));
	s.bodies.push(body.clone());
	json_response(
		200,
		&serde_json::json!({ "data": serde_json::Value::Null }).to_string(),
	)
}

async fn delete_record(
	State(state): State<Shared>,
	Path((account, zone, id)): Path<(String, String, String)>,
	headers: axum::http::HeaderMap,
) -> axum::http::Response<String> {
	assert_eq!(account, ACCOUNT, "wrong account in path");
	assert_eq!(zone, ZONE, "wrong zone in path");
	assert!(!id.is_empty(), "empty record id");
	note_auth(&state, &headers);
	state
		.lock()
		.unwrap()
		.calls
		.push(format!("DELETE {PATH_BASE}/{id}"));
	axum::http::Response::builder()
		.status(StatusCode::NO_CONTENT)
		.body(String::new())
		.expect("build response")
}

async fn mock(initial: Vec<serde_json::Value>) -> (DnsimpleProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		records: initial,
		next_id: 0,
		..Default::default()
	}));
	let app = Router::new()
		.route(
			PATH_BASE,
			axum::routing::get(list_records).post(create_record),
		)
		.route(
			PATH_ITEM,
			axum::routing::patch(update_record).delete(delete_record),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DnsimpleProvider::new(ScopedSecret::new(ZONE, "tok"), ACCOUNT)
		.with_base(format!("http://{addr}/v2"));
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
async fn upsert_creates_subdomain_txt_with_bearer_auth() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert(ZONE, txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.auth.as_deref(), Some("Bearer tok"));
	// One list call (to look for a pre-existing record), then a POST to create.
	let posts = s.calls.iter().filter(|c| c.starts_with("POST")).count();
	let gets = s.calls.iter().filter(|c| c.starts_with("GET")).count();
	assert_eq!(posts, 1, "calls: {:?}", s.calls);
	assert_eq!(gets, 1, "calls: {:?}", s.calls);
	let body = &s.bodies[0];
	assert!(
		body.contains("\"name\":\"_dmarc\""),
		"relative name missing: {body}"
	);
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
	assert!(body.contains("\"content\":\"v=DMARC1; p=none\""), "{body}");
	assert!(body.contains("\"ttl\":3600"), "{body}");
}

#[tokio::test]
async fn upsert_at_apex_uses_empty_name() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert(ZONE, txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = &state.lock().unwrap().bodies[0];
	assert!(body.contains("\"name\":\"\""), "{body}");
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
}

#[tokio::test]
async fn upsert_patches_when_record_already_exists() {
	let existing = vec![record(42, "_dmarc", "TXT", "v=DMARC1; p=none", 3600)];
	let (provider, state) = mock(existing).await;
	provider
		.upsert(ZONE, txt("_dmarc.example.org", "v=DMARC1; p=reject"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let patches = s.calls.iter().filter(|c| c.starts_with("PATCH")).count();
	let posts = s.calls.iter().filter(|c| c.starts_with("POST")).count();
	assert_eq!(patches, 1, "calls: {:?}", s.calls);
	assert_eq!(posts, 0, "calls: {:?}", s.calls);
	let body = &s.bodies[0];
	assert!(
		body.contains("\"content\":\"v=DMARC1; p=reject\""),
		"{body}"
	);
}

#[tokio::test]
async fn delete_absent_record_is_idempotent() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.delete(ZONE, txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert!(
		!s.calls.iter().any(|c| c.starts_with("DELETE")),
		"calls: {:?}",
		s.calls
	);
}

#[tokio::test]
async fn delete_existing_record_sends_delete_call() {
	let existing = vec![record(7, "_dmarc", "TXT", "v=DMARC1", 3600)];
	let (provider, state) = mock(existing).await;
	provider
		.delete(ZONE, txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	let deletes = s.calls.iter().filter(|c| c.starts_with("DELETE")).count();
	assert_eq!(deletes, 1, "calls: {:?}", s.calls);
}

#[tokio::test]
async fn list_parses_records_and_builds_fqdns() {
	let existing = vec![
		record(1, "", "TXT", "v=spf1 -all", 3600),
		record(2, "_dmarc", "TXT", "v=DMARC1; p=none", 3600),
	];
	let (provider, _state) = mock(existing).await;
	let records = provider.list(ZONE).await.expect("list");
	assert_eq!(records.len(), 2);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.kind, RecordKind::Txt);
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(records.iter().any(|r| r.name == "_dmarc.example.org"));
}

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
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert(ZONE, mx).await,
		Err(ProviderError::Unsupported)
	);
	assert!(state.lock().unwrap().calls.is_empty());
}
