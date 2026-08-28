//! Tests for the Cloudflare provider, against an in-process axum mock of the
//! Cloudflare API.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::get;

#[derive(Default)]
struct MockState {
	/// Records the `GET .../dns_records` endpoint returns (for find/list).
	records: Vec<serde_json::Value>,
	/// Captured "METHOD /path" of every request, for assertions.
	calls: Vec<String>,
	/// Body of the most recent POST to `/dns_records` (assertions check the
	/// kind-specific shape: SRV splits priority/weight/port/target into
	/// `data`, TLSA splits usage/selector/matching/cert, etc.).
	last_body: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

async fn list_zones(State(state): State<Shared>) -> axum::Json<serde_json::Value> {
	state.lock().unwrap().calls.push("GET /zones".into());
	axum::Json(serde_json::json!({ "result": [{ "id": "zone123" }] }))
}

async fn records_collection(
	State(state): State<Shared>,
	method: axum::http::Method,
	body: String,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} /dns_records"));
	if method == axum::http::Method::POST {
		s.last_body = Some(body);
	}
	if method == axum::http::Method::GET {
		let result = s.records.clone();
		axum::Json(serde_json::json!({ "result": result, "success": true }))
	} else {
		axum::Json(serde_json::json!({ "success": true }))
	}
}

async fn record_item(
	State(state): State<Shared>,
	method: axum::http::Method,
) -> axum::Json<serde_json::Value> {
	state
		.lock()
		.unwrap()
		.calls
		.push(format!("{method} /record"));
	axum::Json(serde_json::json!({ "success": true }))
}

/// Start the mock and return (provider pointed at it, shared state).
async fn mock(records: Vec<serde_json::Value>) -> (CloudflareProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		records,
		calls: Vec::new(),
		last_body: None,
	}));
	let app = Router::new()
		.route("/zones", get(list_zones))
		.route(
			"/zones/{zone}/dns_records",
			get(records_collection).post(records_collection),
		)
		.route(
			"/zones/{zone}/dns_records/{id}",
			axum::routing::put(record_item).delete(record_item),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = CloudflareProvider::new(ScopedSecret::new("example.org", "tok"))
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
async fn upsert_creates_when_absent() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let calls = state.lock().unwrap().calls.clone();
	// Looked up the zone, searched for the record (empty), then POSTed a new one.
	assert!(calls.contains(&"GET /zones".to_string()), "{calls:?}");
	assert!(
		calls.contains(&"POST /dns_records".to_string()),
		"{calls:?}"
	);
	assert!(!calls.iter().any(|c| c.starts_with("PUT")), "{calls:?}");
}

#[tokio::test]
async fn upsert_updates_when_present() {
	let existing = vec![serde_json::json!({
		"id": "rec1", "type": "TXT", "name": "_dmarc.example.org",
		"content": "old", "ttl": 3600
	})];
	let (provider, state) = mock(existing).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let calls = state.lock().unwrap().calls.clone();
	assert!(calls.contains(&"PUT /record".to_string()), "{calls:?}");
}

#[tokio::test]
async fn list_parses_records() {
	let existing = vec![serde_json::json!({
		"id": "rec1", "type": "TXT", "name": "example.org",
		"content": "v=spf1 -all", "ttl": 3600
	})];
	let (provider, _state) = mock(existing).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].kind, RecordKind::Txt);
	assert_eq!(records[0].value, "v=spf1 -all");
}

#[tokio::test]
async fn delete_absent_is_idempotent_without_delete_call() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let calls = state.lock().unwrap().calls.clone();
	assert!(!calls.iter().any(|c| c.starts_with("DELETE")), "{calls:?}");
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock(Vec::new()).await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	// Least privilege: rejected before any API call.
	assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn mx_upsert_posts_data_object_with_priority_and_host() {
	let (provider, state) = mock(Vec::new()).await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state
		.lock()
		.unwrap()
		.last_body
		.clone()
		.expect("post body captured");
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
	assert!(body.contains("\"host\":\"mail.example.org\""), "{body}");
}

#[test]
fn record_body_uses_data_for_tlsa_and_content_otherwise() {
	let tlsa = DnsRecord {
		name: "_25._tcp.mail.example.org".into(),
		kind: RecordKind::Tlsa,
		value: "3 0 1 abcd".into(),
		ttl: 3600,
	};
	let body = CloudflareProvider::record_body("TLSA", &tlsa).expect("tlsa body");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"usage\":3"), "{body}");
	assert!(body.contains("\"certificate\":\"abcd\""), "{body}");

	let txt = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Txt,
		value: "v=spf1 -all".into(),
		ttl: 3600,
	};
	let body = CloudflareProvider::record_body("TXT", &txt).expect("txt body");
	assert!(body.contains("\"content\":\"v=spf1 -all\""), "{body}");
}

#[test]
fn record_body_splits_srv_into_priority_weight_port_target() {
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org".into(),
		ttl: 3600,
	};
	let body = CloudflareProvider::record_body("SRV", &srv).expect("srv body");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"target\":\"mail.example.org\""), "{body}");
	assert!(!body.contains("\"content\""), "{body}");
}

#[tokio::test]
async fn srv_upsert_posts_with_data_fields() {
	let (provider, state) = mock(Vec::new()).await;
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
	let body = state
		.lock()
		.unwrap()
		.last_body
		.clone()
		.expect("post body captured");
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"weight\":1"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"target\":\"mail.example.org\""), "{body}");
	assert!(!body.contains("\"content\""), "{body}");
}

#[tokio::test]
async fn caa_upsert_posts_with_flags_tag_value_data() {
	let (provider, state) = mock(Vec::new()).await;
	let caa = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Caa,
		value: "0 issue \"letsencrypt.org\"".into(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", caa)
		.await
		.expect("caa upsert");
	let body = state
		.lock()
		.unwrap()
		.last_body
		.clone()
		.expect("post body captured");
	assert!(body.contains("\"type\":\"CAA\""), "{body}");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"flags\":0"), "{body}");
	assert!(body.contains("\"tag\":\"issue\""), "{body}");
	assert!(body.contains("\"value\":\"letsencrypt.org\""), "{body}");
}
