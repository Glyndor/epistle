//! Tests for the DigitalOcean provider, against an in-process axum mock of the
//! v2 REST API.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;

#[derive(Default)]
struct MockState {
	/// Existing records keyed by `kind|name`.
	records: Vec<serde_json::Value>,
	/// Bodies captured from POST/PUT requests.
	bodies: Vec<String>,
	/// Captured "METHOD /path" of every request, for assertions.
	calls: Vec<String>,
	/// Last Authorization header seen.
	auth: Option<String>,
	/// Optional pagination: when set, the GET endpoint appends `links.pages.next`
	/// pointing to a pre-computed absolute URL, and `/next` returns no further
	/// page.
	next_page: bool,
	/// Pre-computed absolute URL used as `links.pages.next` when paginating.
	next_url: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

/// GET /v2/domains/{zone}/records — list with optional pagination.
async fn list_records(
	State(state): State<Shared>,
	method: axum::http::Method,
	headers: axum::http::HeaderMap,
	Path(zone): Path<String>,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} /v2/domains/{zone}/records"));
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	axum::Json(serde_json::json!({
		"domain_records": s.records.clone(),
		"links": {
			"pages": {
				"next": if s.next_page { s.next_url.clone() } else { None }
			}
		}
	}))
}

/// Second page — empty body, no next link.
async fn next_page_handler(State(state): State<Shared>) -> axum::Json<serde_json::Value> {
	state.lock().unwrap().calls.push("GET /next".into());
	axum::Json(serde_json::json!({
		"domain_records": [],
		"links": { "pages": {} }
	}))
}

/// POST /v2/domains/{zone}/records — create. Captures the body and returns a
/// record with id 999.
async fn create_record(
	State(state): State<Shared>,
	method: axum::http::Method,
	headers: axum::http::HeaderMap,
	Path(zone): Path<String>,
	body: String,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} /v2/domains/{zone}/records"));
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	s.bodies.push(body);
	axum::Json(serde_json::json!({
		"domain_record": {
			"id": 999,
			"type": "TXT",
			"name": "@",
			"data": "v=DMARC1",
			"priority": null, "port": null, "weight": null, "flags": null, "tag": null,
			"ttl": 3600
		}
	}))
}

/// PUT/DELETE /v2/domains/{zone}/records/{id}.
async fn record_item(
	State(state): State<Shared>,
	method: axum::http::Method,
	headers: axum::http::HeaderMap,
	Path((zone, id)): Path<(String, String)>,
	body: String,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.calls
		.push(format!("{method} /v2/domains/{zone}/records/{id}"));
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	if method == axum::http::Method::PUT {
		s.bodies.push(body);
	}
	axum::Json(serde_json::json!({
		"domain_record": {
			"id": id.parse::<u64>().unwrap_or(0),
			"type": "TXT",
			"name": "@",
			"data": "v=DMARC1",
			"priority": null, "port": null, "weight": null, "flags": null, "tag": null,
			"ttl": 3600
		}
	}))
}

/// Start the mock and return (provider, shared state). `records` are the
/// existing records the GET endpoint returns; `next_page` enables pagination
/// (which adds an absolute `links.pages.next` URL pointing to `/next`).
async fn mock(records: Vec<serde_json::Value>, next_page: bool) -> (DigitaloceanProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		records,
		next_page,
		..Default::default()
	}));
	let app = Router::new()
		.route(
			"/v2/domains/{zone}/records",
			get(list_records).post(create_record),
		)
		.route("/next", get(next_page_handler))
		.route(
			"/v2/domains/{zone}/records/{id}",
			axum::routing::put(record_item).delete(record_item),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let base = format!("http://{addr}");
	// Pre-compute the absolute pagination URL so the response shape matches
	// DigitalOcean's real `links.pages.next` (absolute, not relative).
	state.lock().unwrap().next_url = Some(format!("{base}/next"));
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider =
		DigitaloceanProvider::new(ScopedSecret::new("example.org", "tok")).with_base(base);
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
async fn upsert_txt_under_subdomain_uses_relative_name_and_bearer_token() {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	// POST'd the create (no existing records).
	assert!(
		s.calls
			.iter()
			.any(|c| c == "POST /v2/domains/example.org/records"),
		"calls: {:?}",
		s.calls
	);
	// Bearer auth, exactly as DigitalOcean documents.
	assert_eq!(s.auth.as_deref(), Some("Bearer tok"));
	let body = s.bodies.last().expect("body");
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
	assert!(body.contains("\"name\":\"_dmarc\""), "{body}");
	// TXT content is unquoted in the wire payload (DO quotes at the zone layer).
	assert!(body.contains("\"data\":\"v=DMARC1; p=none\""), "{body}");
	assert!(body.contains("\"ttl\":3600"), "{body}");
}

#[tokio::test]
async fn upsert_at_apex_uses_at_for_relative_name() {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies.last().unwrap().clone();
	assert!(body.contains("\"name\":\"@\""), "{body}");
}

#[tokio::test]
async fn upsert_updates_when_record_already_exists() {
	let existing = vec![serde_json::json!({
		"id": 42, "type": "TXT", "name": "_dmarc",
		"data": "v=DMARC1; p=none", "ttl": 1800,
		"priority": null, "port": null, "weight": null, "flags": null, "tag": null
	})];
	let (provider, state) = mock(existing, false).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert!(
		s.calls
			.iter()
			.any(|c| c == "PUT /v2/domains/example.org/records/42"),
		"calls: {:?}",
		s.calls
	);
	assert!(
		!s.calls
			.iter()
			.any(|c| c == "POST /v2/domains/example.org/records"),
		"calls: {:?}",
		s.calls
	);
	// And the updated body carries the new value.
	assert!(
		s.bodies
			.iter()
			.any(|b| b.contains("\"data\":\"v=DMARC1; p=reject\"")),
		"{:?}",
		s.bodies
	);
}

#[tokio::test]
async fn delete_is_idempotent_when_record_absent() {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("delete absent is Ok");
	let s = state.lock().unwrap();
	assert!(
		!s.calls.iter().any(|c| c.starts_with("DELETE")),
		"calls: {:?}",
		s.calls
	);
}

#[tokio::test]
async fn list_parses_records_and_emits_fqdn_names() {
	let records = vec![
		serde_json::json!({
			"id": 1, "type": "TXT", "name": "@",
			"data": "v=spf1 -all", "ttl": 3600,
			"priority": null, "port": null, "weight": null, "flags": null, "tag": null
		}),
		serde_json::json!({
			"id": 2, "type": "TXT", "name": "_dmarc",
			"data": "v=DMARC1; p=none", "ttl": 3600,
			"priority": null, "port": null, "weight": null, "flags": null, "tag": null
		}),
	];
	let (provider, _state) = mock(records, false).await;
	let listed = provider.list("example.org").await.expect("list");
	assert_eq!(listed.len(), 2);
	let apex = listed
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(apex.ttl == 3600);
	assert!(
		listed
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.value == "v=DMARC1; p=none"),
		"got: {:?}",
		listed
	);
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock(Vec::new(), false).await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	let s = state.lock().unwrap();
	assert!(s.calls.is_empty(), "no API calls: {:?}", s.calls);
}

#[tokio::test]
async fn mx_upsert_splits_priority_and_target() {
	let (provider, state) = mock(Vec::new(), false).await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state.lock().unwrap().bodies.last().cloned().unwrap();
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"data\":\"mail.example.org\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
}

#[tokio::test]
async fn srv_upsert_splits_into_priority_weight_port_data() {
	let (provider, state) = mock(Vec::new(), false).await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", srv).await.expect("upsert");
	let body = state.lock().unwrap().bodies.last().cloned().unwrap();
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"data\":\"mail.example.org\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
}

#[tokio::test]
async fn list_follows_pagination_next_link() {
	let records = vec![serde_json::json!({
		"id": 1, "type": "TXT", "name": "@",
		"data": "v=spf1 -all", "ttl": 3600,
		"priority": null, "port": null, "weight": null, "flags": null, "tag": null
	})];
	let (provider, state) = mock(records, true).await;
	let _ = provider.list("example.org").await.expect("list");
	let s = state.lock().unwrap();
	assert!(
		s.calls.iter().any(|c| c == "GET /next"),
		"calls: {:?}",
		s.calls
	);
}
