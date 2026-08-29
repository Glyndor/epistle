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
pub(super) struct StoredRecord {
	pub(super) id: u64,
	pub(super) field_type: String,
	pub(super) sub_domain: String,
	pub(super) target: String,
	pub(super) ttl: u32,
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
pub(super) struct MockState {
	pub(super) records: Vec<StoredRecord>,
	pub(super) next_id: u64,
	pub(super) last_headers: HeaderMap,
	pub(super) write_headers: HeaderMap,
	pub(super) write_body: String,
	pub(super) write_method: String,
	pub(super) write_path: String,
	pub(super) refresh_called: bool,
	pub(super) addr: String,
}

pub(super) type Shared = Arc<Mutex<MockState>>;

#[derive(Deserialize, Default)]
struct RecordListQuery {
	field_type: Option<String>,
	sub_domain: Option<String>,
}

async fn list_records(
	State(state): State<Shared>,
	Path(_zone): Path<String>,
	Query(q): Query<RecordListQuery>,
	headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	let ids: Vec<u64> = s
		.records
		.iter()
		.filter(|r| q.field_type.as_deref().is_none_or(|t| t == r.field_type))
		.filter(|r| q.sub_domain.as_deref().is_none_or(|sd| sd == r.sub_domain))
		.map(|r| r.id)
		.collect();
	axum::Json(serde_json::json!(ids))
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

pub(super) async fn mock() -> (OvhProvider, Shared) {
	mock_with(Vec::new()).await
}

pub(super) async fn mock_with(existing: Vec<StoredRecord>) -> (OvhProvider, Shared) {
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
	.with_base(format!("http://{addr}"));
	(provider, state)
}

pub(super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
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

#[test]
fn signature_matches_ovh_python_reference_vector() {
	// The vector is the same one python-ovh ships in
	// `tests/test_client.py::TestClient::test_call_signature`: a GET against
	// `https://eu.api.ovh.com/1.0/auth` at unix 1457018875 with the body
	// empty produces this exact signature header.
	let provider = OvhProvider::new(
		"TDPKJdwZwAQPwKX2".into(),
		"9ufkBmLaTQ9nz5yMUlg79taH0GNnzDjk".into(),
		ScopedSecret::new("example.org", "5mBuy6SUQcRw2ZUxg0cG68BoDKpED4KY"),
	);
	let url = "https://eu.api.ovh.com/1.0/auth";
	let sig = provider.sign("GET", url, "", 1457018875);
	assert_eq!(sig, "$1$e9556054b6309771395efa467c22e627407461ad");
}

#[test]
fn sub_domain_strips_zone_and_uses_empty_for_apex() {
	assert_eq!(OvhProvider::sub_domain("example.org", "example.org"), "");
	assert_eq!(
		OvhProvider::sub_domain("example.org", "_dmarc.example.org"),
		"_dmarc"
	);
	assert_eq!(
		OvhProvider::sub_domain("example.org", "mail.example.org"),
		"mail"
	);
	assert_eq!(
		OvhProvider::sub_domain("example.org", "_dmarc.example.org."),
		"_dmarc"
	);
}

#[test]
fn endpoint_alias_resolves_to_regional_base() {
	assert_eq!(resolve_base(None), "https://eu.api.ovh.com/1.0".to_string());
	assert_eq!(
		resolve_base(Some("ovh-eu")),
		"https://eu.api.ovh.com/1.0".to_string()
	);
	assert_eq!(
		resolve_base(Some("ovh-ca")),
		"https://ca.api.ovh.com/1.0".to_string()
	);
	assert_eq!(
		resolve_base(Some("ovh-us")),
		"https://api.us.ovhcloud.com/1.0".to_string()
	);
	assert_eq!(
		resolve_base(Some("https://private.example.com/1.0")),
		"https://private.example.com/1.0".to_string()
	);
	assert_eq!(
		resolve_base(Some("not-a-region")),
		"https://eu.api.ovh.com/1.0".to_string()
	);
}

#[tokio::test]
async fn upsert_creates_txt_with_relative_subdomain_and_signed_headers() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let snapshot = {
		let s = state.lock().unwrap();
		(
			s.write_method.clone(),
			s.write_path.clone(),
			s.write_body.clone(),
			s.addr.clone(),
			s.write_headers.clone(),
			s.refresh_called,
		)
	};
	let (write_method, write_path, write_body, addr, write_headers, refresh_called) = snapshot;
	assert_eq!(write_method, "POST");
	assert_eq!(write_path, "/domain/zone/example.org/record");
	let body: serde_json::Value = serde_json::from_str(&write_body).expect("body json");
	assert_eq!(body["fieldType"], "TXT");
	assert_eq!(body["subDomain"], "_dmarc");
	assert_eq!(body["target"], "v=DMARC1; p=none");
	assert_eq!(body["ttl"], 3600);
	assert_eq!(write_headers.get("X-Ovh-Application").unwrap(), "AKID");
	assert_eq!(write_headers.get("X-Ovh-Consumer").unwrap(), "CK");
	// Reconstruct the signature independently of `OvhProvider::sign`, so a
	// bug in the implementation cannot match a buggy `expected`.
	let timestamp: u64 = write_headers
		.get("X-Ovh-Timestamp")
		.unwrap()
		.to_str()
		.unwrap()
		.parse()
		.unwrap();
	let full_url = format!("http://{addr}/domain/zone/example.org/record");
	let to_sign = format!("secret+CK+POST+{full_url}+{write_body}+{timestamp}");
	let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, to_sign.as_bytes());
	let expected = format!("$1${}", hex_lower(digest.as_ref()));
	let sig = write_headers
		.get("X-Ovh-Signature")
		.unwrap()
		.to_str()
		.unwrap()
		.to_string();
	assert_eq!(sig, expected, "X-Ovh-Signature mismatch");
	assert!(refresh_called, "POST /refresh must follow the write");
	// Round-trip through `provider.sign()` to also exercise that public
	// surface; this passes when the impl is correct and self-consistent.
	let _ = provider.sign("POST", &full_url, &write_body, timestamp);
}

#[tokio::test]
async fn upsert_at_apex_uses_empty_subdomain() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body: serde_json::Value = serde_json::from_str(&s.write_body).expect("body json");
	assert_eq!(body["subDomain"], "");
	assert_eq!(body["fieldType"], "TXT");
	assert_eq!(s.write_path, "/domain/zone/example.org/record");
}

#[tokio::test]
async fn upsert_updates_existing_record_without_duplicating() {
	let existing = vec![StoredRecord {
		id: 42,
		field_type: "TXT".into(),
		sub_domain: "_dmarc".into(),
		target: "v=DMARC1; p=none".into(),
		ttl: 3600,
	}];
	let (provider, state) = mock_with(existing).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.write_method, "PUT");
	assert_eq!(s.write_path, "/domain/zone/example.org/record/42");
	let body: serde_json::Value = serde_json::from_str(&s.write_body).expect("body json");
	assert_eq!(body["target"], "v=DMARC1; p=reject");
	// No duplicate was created.
	let matching = s
		.records
		.iter()
		.filter(|r| r.sub_domain == "_dmarc" && r.field_type == "TXT")
		.count();
	assert_eq!(matching, 1, "expected exactly one matching record");
}

#[tokio::test]
async fn upsert_refreshes_zone_after_writing() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert!(s.refresh_called, "POST /refresh must follow the write");
}

#[tokio::test]
async fn delete_absent_record_is_idempotent_and_skips_refresh() {
	let (provider, state) = mock().await;
	// No matching record in the mock: find_record_id returns None, so we
	// never call DELETE or refresh.
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(s.records.len(), 0);
	assert!(s.write_path.is_empty(), "no write call: {}", s.write_path);
	assert!(!s.refresh_called, "no refresh when nothing was deleted");
}

#[tokio::test]
async fn delete_present_record_calls_delete_then_refresh() {
	let existing = vec![StoredRecord {
		id: 7,
		field_type: "TXT".into(),
		sub_domain: "_dmarc".into(),
		target: "v=DMARC1".into(),
		ttl: 3600,
	}];
	let (provider, state) = mock_with(existing).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert!(s.records.is_empty(), "delete removed the record");
	assert_eq!(s.write_method, "DELETE");
	assert_eq!(s.write_path, "/domain/zone/example.org/record/7");
	assert!(s.refresh_called, "POST /refresh must follow the delete");
}

#[tokio::test]
async fn list_parses_records_and_strips_txt_quotes() {
	let existing = vec![
		StoredRecord {
			id: 11,
			field_type: "TXT".into(),
			sub_domain: "".into(),
			target: "\"v=spf1 -all\"".into(), // OVH silently quotes TXT.
			ttl: 3600,
		},
		StoredRecord {
			id: 12,
			field_type: "TXT".into(),
			sub_domain: "_dmarc".into(),
			target: "\"v=DMARC1; p=none\"".into(),
			ttl: 3600,
		},
	];
	let (provider, _state) = mock_with(existing).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 2);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.kind, RecordKind::Txt);
	assert_eq!(apex.value, "v=spf1 -all");
	assert_eq!(apex.ttl, 3600);
	assert!(
		records
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.value == "v=DMARC1; p=none")
	);
}
