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
pub(in super::super) struct Call {
	pub(in super::super) method: Method,
	pub(in super::super) path: String,
	pub(in super::super) body: String,
	pub(in super::super) auth: Option<String>,
}

#[derive(Default)]
pub(in super::super) struct MockState {
	/// Records the `GET /domains/{zone}/records` endpoint returns. The
	/// full zone list, used for `list`.
	pub(in super::super) zone_records: serde_json::Value,
	/// Per-`(kind, name)` record sets. Populated by PUT, cleared by
	/// DELETE, returned by GET. Tests pre-populate it to simulate an
	/// existing set; the GET handler returns an empty array for an
	/// absent key so a fresh zone reads as `[]`.
	pub(in super::super) per_name_records:
		std::collections::HashMap<(String, String), serde_json::Value>,
	/// Every request seen, in order.
	pub(in super::super) calls: Vec<Call>,
	/// When set, every endpoint answers this status code with an empty body.
	pub(in super::super) fail_with: Option<u16>,
}

pub(in super::super) type Shared = Arc<Mutex<MockState>>;

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
pub(in super::super) fn parse_per_name(path: &str) -> Option<(String, String)> {
	let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
	if parts.len() == 5 && parts[0] == "domains" && parts[2] == "records" {
		Some((parts[3].to_string(), parts[4].to_string()))
	} else {
		None
	}
}

/// Start the mock and return (provider pointed at it, shared state).
pub(in super::super) async fn mock() -> (GodaddyProvider, Shared) {
	mock_with(serde_json::json!([])).await
}

pub(in super::super) async fn mock_with(
	zone_records: serde_json::Value,
) -> (GodaddyProvider, Shared) {
	mock_with_per_name(zone_records, Default::default()).await
}

pub(in super::super) async fn mock_with_per_name(
	zone_records: serde_json::Value,
	per_name_records: std::collections::HashMap<(String, String), serde_json::Value>,
) -> (GodaddyProvider, Shared) {
	let (base, state) = mock_with_per_name_raw(zone_records, per_name_records).await;
	let provider = GodaddyProvider::new(
		"ak_under_test".to_string(),
		"sk_under_test_secret".to_string(),
		"example.org".to_string(),
	)
	.with_base(crate::net::HttpsUrl::loopback_http(&base).unwrap());
	(provider, state)
}

/// Start the mock and return `(base_url, shared_state)`. The caller
/// builds the provider so a test can configure a non-default zone
/// (the trailing-dot case, for example) and still point at the same
/// mock the other tests use.
pub(in super::super) async fn mock_with_per_name_raw(
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

pub(in super::super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord::new(name.to_string(), RecordKind::Txt, value.to_string(), 3600)
}

mod errors;
mod listing;
mod upsert;
