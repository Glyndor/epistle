//! Tests for the Cloudflare `proxied` flag: every record epistle publishes
//! must go out with `proxied: false` because mail clients and other servers
//! cannot reach the mail server through the proxy, and a `list` against a
//! zone that has been hand-configured with the orange cloud must surface
//! the flag so `epistle status` can report it.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::get;

#[derive(Default)]
struct ProxiedState {
	records: Vec<serde_json::Value>,
	bodies: Vec<String>,
}

type ProxiedShared = Arc<Mutex<ProxiedState>>;

async fn list_zones(State(_state): State<ProxiedShared>) -> axum::Json<serde_json::Value> {
	axum::Json(serde_json::json!({ "result": [{ "id": "zone123" }] }))
}

async fn records_collection(
	State(state): State<ProxiedShared>,
	method: axum::http::Method,
	body: String,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	if method == axum::http::Method::POST {
		state.lock().unwrap().bodies.push(body);
	}
	let result = state.lock().unwrap().records.clone();
	let ok = axum::http::StatusCode::OK;
	if method == axum::http::Method::GET {
		(
			ok,
			axum::Json(serde_json::json!({ "result": result, "success": true })),
		)
	} else {
		(ok, axum::Json(serde_json::json!({ "success": true })))
	}
}

async fn record_item(
	State(state): State<ProxiedShared>,
	method: axum::http::Method,
	body: String,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	if method == axum::http::Method::PUT {
		state.lock().unwrap().bodies.push(body);
	}
	(
		axum::http::StatusCode::OK,
		axum::Json(serde_json::json!({ "success": true })),
	)
}

async fn proxied_mock(records: Vec<serde_json::Value>) -> (CloudflareProvider, ProxiedShared) {
	let state: ProxiedShared = Arc::new(Mutex::new(ProxiedState {
		records,
		..ProxiedState::default()
	}));
	let app = Router::new()
		.route("/zones", get(list_zones))
		.route(
			"/zones/{zone}/dns_records",
			get(records_collection).post(records_collection),
		)
		.route(
			"/zones/{zone}/dns_records/{id}",
			axum::routing::put(record_item),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = CloudflareProvider::new(ScopedSecret::new(
		"example.org",
		crate::test_fixtures::api_token(),
	))
	.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

fn body_at(state: &ProxiedShared, index: usize) -> serde_json::Value {
	serde_json::from_str(&state.lock().unwrap().bodies[index]).unwrap()
}

fn a(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::A,
		value: value.to_string(),
		ttl: 3600,
		proxied: None,
	}
}

/// Every write must carry `proxied: false`. The proxy only handles HTTP/S
/// traffic, so a record the proxy takes over never reaches the mail server:
/// SMTP / IMAP / POP3 / submission all need direct delivery to the IP and
/// the proxy refuses to forward non-HTTP traffic.
#[tokio::test]
async fn upsert_posts_proxied_false_for_a_record() {
	let (provider, state) = proxied_mock(Vec::new()).await;
	provider
		.upsert("example.org", a("mail.example.org", "192.0.2.1"))
		.await
		.expect("upsert");
	let body = body_at(&state, 0);
	assert_eq!(body["proxied"], serde_json::json!(false));
}

/// The MX target host is the mail hostname (`mail.<domain>`). An A record
/// for it that the proxy takes over also breaks: the proxy swallows SMTP
/// traffic instead of forwarding it. Same `proxied: false` requirement.
#[tokio::test]
async fn upsert_posts_proxied_false_for_aaaa_record() {
	let (provider, state) = proxied_mock(Vec::new()).await;
	let mut record = a("mail.example.org", "192.0.2.1");
	record.kind = RecordKind::Aaaa;
	record.value = "2001:db8::1".to_string();
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = body_at(&state, 0);
	assert_eq!(body["proxied"], serde_json::json!(false));
}

/// `autoconfig` and `autodiscover` are CNAMEs the mail server resolves and
/// serves from, but the proxy can still swallow traffic to them if its
/// operator enables the orange cloud on those names. epistle must always pin
/// them to `proxied: false` to keep the resolver-to-client path open.
#[tokio::test]
async fn upsert_posts_proxied_false_for_cname_record() {
	let (provider, state) = proxied_mock(Vec::new()).await;
	let mut record = a("autoconfig.example.org", "192.0.2.1");
	record.kind = RecordKind::Cname;
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = body_at(&state, 0);
	assert_eq!(body["proxied"], serde_json::json!(false));
}

/// `list()` must surface `proxied: true` for a record the operator has
/// switched to the orange cloud. A `None` here would mean `status` never
/// sees the proxy problem.
#[tokio::test]
async fn list_surfaces_proxied_true_for_an_a_record_through_the_orange_cloud() {
	let existing = vec![serde_json::json!({
		"id": "rec1",
		"type": "A",
		"name": "mail.example.org",
		"content": "192.0.2.1",
		"ttl": 3600,
		"proxied": true,
	})];
	let (provider, _state) = proxied_mock(existing).await;
	let records = provider.list("example.org").await.expect("list");
	let rec = records
		.iter()
		.find(|r| r.name == "mail.example.org" && r.kind == RecordKind::A)
		.expect("the record is returned");
	assert_eq!(rec.proxied, Some(true));
}

/// A record that the operator has set to DNS only reads back as
/// `proxied: false`. `status` uses the absence of `proxied: true` as a
/// pass for the mail names; the API always sends the boolean back, so
/// `Some(false)` is the right answer.
#[tokio::test]
async fn list_surfaces_proxied_false_for_a_dns_only_record() {
	let existing = vec![serde_json::json!({
		"id": "rec1",
		"type": "A",
		"name": "mail.example.org",
		"content": "192.0.2.1",
		"ttl": 3600,
		"proxied": false,
	})];
	let (provider, _state) = proxied_mock(existing).await;
	let records = provider.list("example.org").await.expect("list");
	let rec = records
		.iter()
		.find(|r| r.name == "mail.example.org")
		.expect("the record is returned");
	assert_eq!(rec.proxied, Some(false));
}

/// The null MX (RFC 7505) keeps its root target: an empty `host` is not a
/// null MX.
#[tokio::test]
async fn upsert_sends_the_null_mx_with_the_root_target() {
	let (provider, state) = proxied_mock(Vec::new()).await;
	let mut record = a("www.example.org", "0 .");
	record.kind = RecordKind::Mx;
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = body_at(&state, 0);
	assert_eq!(
		body["data"],
		serde_json::json!({ "priority": 0, "host": "." })
	);
	assert!(body.get("proxied").is_none(), "{body}");
}

/// A zone longer than one page is read to its last page, and an MX reads
/// back as `priority target`.
#[tokio::test]
async fn list_reads_every_page_and_keeps_the_mx_priority() {
	let (base, seen) = crate::dns::tests::uri_probe::probe(&[
		r#"{"result":[{"id":"zone1"}]}"#,
		r#"{"result":[{"id":"r1","name":"www.example.org","type":"A","content":"192.0.2.1","ttl":300}],"result_info":{"page":1,"total_pages":2}}"#,
		r#"{"result":[{"id":"r2","name":"www.example.org","type":"MX","content":".","priority":0,"ttl":300}],"result_info":{"page":2,"total_pages":2}}"#,
	])
	.await;
	let provider = CloudflareProvider::new(ScopedSecret::new(
		"example.org",
		crate::test_fixtures::api_token(),
	))
	.with_base(base);
	let records = provider.list("example.org").await.expect("list");
	let values: Vec<String> = records
		.iter()
		.map(|r| format!("{} {}", r.kind.as_str(), r.value))
		.collect();
	assert_eq!(values, vec!["A 192.0.2.1", "MX 0 ."]);
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"GET /zones?name=example.org",
			"GET /zones/zone1/dns_records?per_page=100&page=1",
			"GET /zones/zone1/dns_records?per_page=100&page=2",
		]
	);
}
