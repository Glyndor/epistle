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
	/// Body of the most recent POST or PUT to `/dns_records` (assertions check the
	/// kind-specific shape: SRV splits priority/weight/port/target into
	/// `data`, TLSA splits usage/selector/matching/cert, etc.).
	last_body: Option<String>,
	/// Every POST/PUT body, in order.
	bodies: Vec<String>,
	/// Answer 400 to a write whose body carries `tags` (a Free plan zone).
	reject_tags: bool,
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
		(
			ok,
			axum::Json(serde_json::json!({ "result": result, "success": true })),
		)
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

#[tokio::test]
async fn mx_upsert_posts_data_object_with_priority_and_host() {
	let (provider, state) = mock(Vec::new()).await;
	let mx = DnsRecord::new("example.org", RecordKind::Mx, "10 mail.example.org", 3600);
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
	let tlsa = DnsRecord::new(
		"_25._tcp.mail.example.org",
		RecordKind::Tlsa,
		"3 0 1 abcd",
		3600,
	);
	let body = CloudflareProvider::record_body("TLSA", &tlsa).expect("tlsa body");
	assert!(body.contains("\"data\""), "{body}");
	assert!(body.contains("\"usage\":3"), "{body}");
	assert!(body.contains("\"certificate\":\"abcd\""), "{body}");

	let txt = DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 -all", 3600);
	let body = CloudflareProvider::record_body("TXT", &txt).expect("txt body");
	// TXT content goes quoted, the form Cloudflare's API documents.
	assert!(body.contains(r#""content":"\"v=spf1 -all\"""#), "{body}");
}

#[test]
fn record_body_splits_srv_into_priority_weight_port_target() {
	let srv = DnsRecord::new(
		"_submissions._tcp.example.org",
		RecordKind::Srv,
		"0 1 465 mail.example.org",
		3600,
	);
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
	let caa = DnsRecord::new(
		"example.org",
		RecordKind::Caa,
		"0 issue \"letsencrypt.org\"",
		3600,
	);
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

#[tokio::test]
async fn create_body_carries_the_comment_field() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(state.lock().unwrap().last_body.as_deref().unwrap()).unwrap();
	assert_eq!(body["comment"], expected_description());
}

#[tokio::test]
async fn update_body_sets_the_comment_field_too() {
	let existing = vec![serde_json::json!({
		"id": "rec1", "type": "TXT", "name": "_dmarc.example.org",
		"content": "v=DMARC1; p=none", "ttl": 3600, "comment": "set by hand"
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
	assert!(
		s.calls.iter().any(|c| c.starts_with("PUT ")),
		"{:?}",
		s.calls
	);
	let body: serde_json::Value = serde_json::from_str(s.last_body.as_deref().unwrap()).unwrap();
	assert_eq!(body["comment"], expected_description());
}

#[test]
fn every_record_kind_body_carries_the_comment() {
	let rec = |kind, value: &str| DnsRecord::new("x.example.org", kind, value, 300);
	let cases = [
		(RecordKind::A, "192.0.2.1"),
		(RecordKind::Mx, "10 mail.example.org."),
		(RecordKind::Srv, "0 1 443 mail.example.org."),
		(RecordKind::Tlsa, "3 1 1 abcd"),
		(RecordKind::Caa, "0 issue \"letsencrypt.org\""),
	];
	for (kind, value) in cases {
		let r = rec(kind.clone(), value);
		let body = CloudflareProvider::record_body(kind.as_str(), &r).unwrap();
		let v: serde_json::Value = serde_json::from_str(&body).unwrap();
		assert_eq!(v["comment"], expected_description(), "{}", kind.as_str());
	}
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

#[tokio::test]
async fn create_carries_the_host_tag() {
	let (provider, state) = tagging_mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body = body_at(&state, 0);
	assert_eq!(
		body["tags"],
		serde_json::json!(["epistle:mail.example.org"])
	);
	assert_eq!(body["comment"], expected_description());
}

#[tokio::test]
async fn update_replaces_the_epistle_tag_and_keeps_operator_tags() {
	let existing = vec![serde_json::json!({
		"id": "rec1", "type": "TXT", "name": "_dmarc.example.org",
		"content": "v=DMARC1; p=none", "ttl": 3600,
		"tags": ["team:mail", "epistle:old.example.org", "env:prod"]
	})];
	let (provider, state) = tagging_mock(existing, false).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	assert!(
		state
			.lock()
			.unwrap()
			.calls
			.iter()
			.any(|c| c.starts_with("PUT "))
	);
	let body = body_at(&state, 0);
	assert_eq!(
		body["tags"],
		serde_json::json!(["team:mail", "env:prod", "epistle:mail.example.org"])
	);
	assert_eq!(body["comment"], expected_description());
}

#[tokio::test]
async fn refused_tags_retry_once_without_them_and_later_writes_skip_tags() {
	let (provider, state) = tagging_mock(Vec::new(), true).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("first upsert falls back to no tags");
	{
		let s = state.lock().unwrap();
		// One refused POST (not stored), one accepted POST without tags.
		let posts = s.calls.iter().filter(|c| *c == "POST /dns_records").count();
		assert_eq!(posts, 2, "{:?}", s.calls);
		assert_eq!(s.bodies.len(), 1);
	}
	let first = body_at(&state, 0);
	assert!(first.get("tags").is_none(), "{first}");
	assert_eq!(first["comment"], expected_description());
	provider
		.upsert("example.org", txt("_spf.example.org", "v=spf1 -all"))
		.await
		.expect("second upsert");
	let posts = state
		.lock()
		.unwrap()
		.calls
		.iter()
		.filter(|c| *c == "POST /dns_records")
		.count();
	assert_eq!(posts, 3, "second write must not try tags again");
}

#[tokio::test]
async fn accepted_tags_stay_on_for_later_writes() {
	let (provider, state) = tagging_mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	provider
		.upsert("example.org", txt("_spf.example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	assert_eq!(
		body_at(&state, 1)["tags"],
		serde_json::json!(["epistle:mail.example.org"])
	);
}

#[tokio::test]
async fn without_a_hostname_no_tags_are_sent() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	assert!(body_at(&state, 0).get("tags").is_none());
}

#[path = "tests_txt_forms.rs"]
mod txt_forms;

#[path = "tests_contract.rs"]
mod contract;
