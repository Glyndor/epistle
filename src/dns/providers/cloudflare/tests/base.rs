//! Tests for the Cloudflare provider, against an in-process axum mock of the
//! Cloudflare API.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::Query;
use axum::extract::State;
use axum::routing::get;

#[derive(Default)]
struct MockState {
	/// Records the `GET .../dns_records` endpoint returns (for find/list).
	records: Vec<serde_json::Value>,
	/// Captured "METHOD /path" of every request, for assertions.
	calls: Vec<String>,
	/// Body of the most recent POST or PUT to `/dns_records` (assertions check the
	/// kind-specific shape: SRV splits priority/weight/port/target into
	/// `data`, TLSA splits usage/selector/matching/cert, etc.).
	last_body: Option<String>,
	/// Every POST/PUT body, in order.
	bodies: Vec<String>,
	/// Answer 400 to a write whose body carries `tags` (a Free plan zone).
	reject_tags: bool,
	/// What a listing says in `result_info.total_pages`; nothing when `None`.
	total_pages: Option<u32>,
	/// The zone the lookup refuses to answer about: Cloudflare answers 403
	/// for it, as it does for a zone the token may not read.
	zone_denied: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

async fn list_zones(
	State(state): State<Shared>,
	Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
	let mut s = state.lock().unwrap();
	s.calls.push("GET /zones".into());
	// A zone the account refuses to answer about.
	if let (Some(denied), Some(name)) = (
		s.zone_denied.as_deref(),
		query.get("name").map(String::as_str),
	) && denied == name
	{
		return Err(axum::http::StatusCode::FORBIDDEN);
	}
	// A zone lookup names the zone it asks for. The mock holds one zone,
	// the one the credential covers, so a name below it is not a zone.
	if let Some(name) = query.get("name")
		&& name != "example.org"
	{
		return Ok(axum::Json(
			serde_json::json!({ "result": [], "success": true }),
		));
	}
	Ok(axum::Json(
		serde_json::json!({ "result": [{ "id": "zone123" }], "success": true }),
	))
}

async fn records_collection(
	State(state): State<Shared>,
	method: axum::http::Method,
	body: String,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} /dns_records"));
	if method == axum::http::Method::POST {
		if s.reject_tags && body.contains("\"tags\"") {
			return tags_refused();
		}
		s.bodies.push(body.clone());
		s.last_body = Some(body);
	}
	let ok = axum::http::StatusCode::OK;
	if method == axum::http::Method::GET {
		let result = s.records.clone();
		let mut body = serde_json::json!({ "result": result, "success": true });
		if let Some(total_pages) = s.total_pages {
			body["result_info"] = serde_json::json!({ "total_pages": total_pages });
		}
		(ok, axum::Json(body))
	} else {
		(ok, axum::Json(serde_json::json!({ "success": true })))
	}
}

fn tags_refused() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	(
		axum::http::StatusCode::BAD_REQUEST,
		axum::Json(serde_json::json!({ "success": false, "errors": [{ "code": 9300 }] })),
	)
}

async fn record_item(
	State(state): State<Shared>,
	method: axum::http::Method,
	uri: axum::http::Uri,
	body: String,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	let mut s = state.lock().unwrap();
	s.calls.push(format!("{method} {}", uri.path()));
	if method == axum::http::Method::PUT {
		if s.reject_tags && body.contains("\"tags\"") {
			return tags_refused();
		}
		s.bodies.push(body.clone());
		s.last_body = Some(body);
	}
	(
		axum::http::StatusCode::OK,
		axum::Json(serde_json::json!({ "success": true })),
	)
}

/// Start the mock and return (provider pointed at it, shared state).
async fn mock(records: Vec<serde_json::Value>) -> (CloudflareProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		records,
		..MockState::default()
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
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord::new(name.to_string(), RecordKind::Txt, value.to_string(), 3600)
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
		"content": "v=DMARC1; p=none", "ttl": 3600
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
	assert!(
		calls
			.iter()
			.any(|c| c == "PUT /zones/zone123/dns_records/rec1"),
		"{calls:?}"
	);
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

/// A TXT delete with a value must remove only the matching record
/// and leave sibling TXT records at the same owner. Two ACME DNS-01
/// challenges at the same owner is the canonical case: cleaning up
/// one certificate order's challenge must not wipe the second
/// order's. Cloudflare addresses every record by id, so the fix is
/// to find the id whose content matches the value (not the first
/// by type+name) and delete that one alone. The records below
/// intentionally put the sibling first, so a regression that
/// returns the first record by type+name deletes the wrong id.
#[tokio::test]
async fn txt_delete_with_a_value_drops_only_the_matching_challenge() {
	let existing = vec![
		serde_json::json!({
			"id": "rec-bbbb",
			"type": "TXT",
			"name": "_acme-challenge.example.org",
			"content": "token-bbbb",
			"ttl": 60,
		}),
		serde_json::json!({
			"id": "rec-aaaa",
			"type": "TXT",
			"name": "_acme-challenge.example.org",
			"content": "token-aaaa",
			"ttl": 60,
		}),
	];
	let (provider, state) = mock(existing).await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let calls = state.lock().unwrap().calls.clone();
	// The provider looked the records up, found the matching id,
	// and deleted only that one. The sibling record's id never
	// appears in a DELETE.
	assert!(
		calls
			.iter()
			.any(|c| c == "DELETE /zones/zone123/dns_records/rec-aaaa"),
		"the matching id is deleted: {calls:?}"
	);
	assert!(
		!calls
			.iter()
			.any(|c| c.starts_with("DELETE /zones/zone123/dns_records/rec-bbbb")),
		"sibling id must not be deleted: {calls:?}"
	);
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

/// The exact string the owner expects in the provider panel.
fn expected_description() -> String {
	format!("Epistle v{}", env!("CARGO_PKG_VERSION"))
}

/// A provider that tags with `mail.example.org`, against the same mock.
async fn tagging_mock(
	records: Vec<serde_json::Value>,
	reject_tags: bool,
) -> (CloudflareProvider, Shared) {
	let (provider, state) = mock(records).await;
	state.lock().unwrap().reject_tags = reject_tags;
	(provider.with_hostname("mail.example.org"), state)
}

fn body_at(state: &Shared, index: usize) -> serde_json::Value {
	serde_json::from_str(&state.lock().unwrap().bodies[index]).unwrap()
}

mod txt_forms;

mod contract;

mod zone;

mod host_tags;
mod record_bodies;

mod exact;
