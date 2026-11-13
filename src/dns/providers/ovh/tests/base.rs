//! Tests for the OVH DNS provider against an in-process axum mock.
//!
//! The mock holds a small set of records (id, fieldType, subDomain, target,
//! ttl) and replays them through the same endpoints OVH's production API
//! exposes, with the real JSON shape OVH returns — not a parse-friendly
//! surrogate — so a working `list` parser proves it understands the live
//! contract.

use std::sync::{Arc, Mutex};

use super::*;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use serde::Deserialize;

/// A record the mock keeps in memory and hands back as JSON in the same
/// shape OVH's `/record/{id}` returns.
#[derive(Clone)]
pub(in super::super) struct StoredRecord {
	pub(in super::super) id: u64,
	pub(in super::super) field_type: String,
	pub(in super::super) sub_domain: String,
	pub(in super::super) target: String,
	pub(in super::super) ttl: u32,
}

impl StoredRecord {
	fn to_json(&self) -> serde_json::Value {
		serde_json::json!({
			"id": self.id,
			"zone": "example.org",
			"fieldType": self.field_type,
			"subDomain": self.sub_domain,
			"target": self.target,
			"ttl": self.ttl,
		})
	}
}

#[derive(Default)]
pub(in super::super) struct MockState {
	pub(in super::super) records: Vec<StoredRecord>,
	pub(in super::super) next_id: u64,
	pub(in super::super) last_headers: HeaderMap,
	pub(in super::super) write_headers: HeaderMap,
	pub(in super::super) write_body: String,
	pub(in super::super) write_method: String,
	pub(in super::super) write_path: String,
	pub(in super::super) refresh_called: bool,
	pub(in super::super) addr: String,
	/// How many `GET /record/{id}` the mock answered.
	pub(in super::super) reads: usize,
	/// Every write in order: `create`, `update <id>` or `delete <id>`.
	pub(in super::super) writes: Vec<String>,
	/// The `target` each create and update carried, in order.
	pub(in super::super) targets: Vec<String>,
}

pub(in super::super) type Shared = Arc<Mutex<MockState>>;

#[derive(Deserialize, Default)]
struct RecordListQuery {
	field_type: Option<String>,
	sub_domain: Option<String>,
}

async fn list_records(
	State(state): State<Shared>,
	Path(zone): Path<String>,
	Query(q): Query<RecordListQuery>,
	headers: HeaderMap,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	// A zone OVH does not hold: it answers 404, which says the zone is
	// not there, not that the provider could not answer.
	if zone != "example.org" {
		return Err(axum::http::StatusCode::NOT_FOUND);
	}
	let ids: Vec<u64> = s
		.records
		.iter()
		.filter(|r| q.field_type.as_deref().is_none_or(|t| t == r.field_type))
		.filter(|r| q.sub_domain.as_deref().is_none_or(|sd| sd == r.sub_domain))
		.map(|r| r.id)
		.collect();
	Ok(axum::Json(serde_json::json!(ids)))
}

async fn create_record(
	State(state): State<Shared>,
	Path(zone): Path<String>,
	headers: HeaderMap,
	body: String,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	let mut s = state.lock().unwrap();
	s.last_headers = headers.clone();
	s.write_headers = headers;
	s.write_path = format!("/domain/zone/{}/record", zone);
	s.write_body = body.clone();
	s.write_method = "POST".into();
	let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
	s.writes.push("create".into());
	s.targets
		.push(parsed["target"].as_str().unwrap_or("").to_string());
	s.next_id += 1;
	let id = s.next_id;
	let rec = StoredRecord {
		id,
		field_type: parsed["fieldType"].as_str().unwrap_or("").to_string(),
		sub_domain: parsed["subDomain"].as_str().unwrap_or("").to_string(),
		target: parsed["target"].as_str().unwrap_or("").to_string(),
		ttl: parsed["ttl"].as_u64().unwrap_or(0) as u32,
	};
	s.records.push(rec);
	(
		axum::http::StatusCode::OK,
		axum::Json(serde_json::json!(id)),
	)
}

async fn read_record(
	State(state): State<Shared>,
	Path((_zone, id)): Path<(String, u64)>,
	headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	s.reads += 1;
	let rec = s.records.iter().find(|r| r.id == id).cloned();
	match rec {
		Some(r) => axum::Json(r.to_json()),
		None => axum::Json(serde_json::json!({"id": id, "_missing": true})),
	}
}

async fn update_record(
	State(state): State<Shared>,
	Path((zone, id)): Path<(String, u64)>,
	headers: HeaderMap,
	body: String,
) -> axum::http::StatusCode {
	let mut s = state.lock().unwrap();
	s.last_headers = headers.clone();
	s.write_headers = headers;
	s.write_path = format!("/domain/zone/{}/record/{}", zone, id);
	s.write_body = body.clone();
	s.write_method = "PUT".into();
	let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
	s.writes.push(format!("update {id}"));
	s.targets
		.push(parsed["target"].as_str().unwrap_or("").to_string());
	if let Some(r) = s.records.iter_mut().find(|r| r.id == id) {
		r.field_type = parsed["fieldType"].as_str().unwrap_or("").to_string();
		r.sub_domain = parsed["subDomain"].as_str().unwrap_or("").to_string();
		r.target = parsed["target"].as_str().unwrap_or("").to_string();
		r.ttl = parsed["ttl"].as_u64().unwrap_or(0) as u32;
	}
	axum::http::StatusCode::NO_CONTENT
}

async fn delete_record(
	State(state): State<Shared>,
	Path((zone, id)): Path<(String, u64)>,
	headers: HeaderMap,
) -> axum::http::StatusCode {
	let mut s = state.lock().unwrap();
	s.last_headers = headers.clone();
	s.write_headers = headers;
	s.write_path = format!("/domain/zone/{}/record/{}", zone, id);
	s.write_method = "DELETE".into();
	s.write_body = String::new();
	s.writes.push(format!("delete {id}"));
	s.records.retain(|r| r.id != id);
	axum::http::StatusCode::NO_CONTENT
}

async fn refresh_zone(
	State(state): State<Shared>,
	Path(_zone): Path<String>,
	headers: HeaderMap,
) -> axum::http::StatusCode {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	s.refresh_called = true;
	axum::http::StatusCode::NO_CONTENT
}

pub(in super::super) async fn mock() -> (OvhProvider, Shared) {
	mock_with(Vec::new()).await
}

pub(in super::super) async fn mock_with(existing: Vec<StoredRecord>) -> (OvhProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		next_id: 0,
		records: existing,
		..Default::default()
	}));
	let app = Router::new()
		.route(
			"/domain/zone/{zone}/record",
			get(list_records).post(create_record),
		)
		.route(
			"/domain/zone/{zone}/record/{id}",
			get(read_record).put(update_record).delete(delete_record),
		)
		.route("/domain/zone/{zone}/refresh", post(refresh_zone))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	state.lock().unwrap().addr = addr.to_string();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = OvhProvider::new(
		"AKID".into(),
		"secret".into(),
		ScopedSecret::new("example.org", "CK"),
	)
	.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

pub(in super::super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
		proxied: None,
	}
}

fn hex_lower(bytes: &[u8]) -> String {
	use std::fmt::Write;
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(out, "{byte:02x}");
	}
	out
}

mod delete_and_list;
mod signing;
mod upsert;

mod exact;
mod guarded;
