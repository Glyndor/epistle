//! Tests for the deSEC provider against an in-process axum mock.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::get;

#[derive(Default)]
struct MockState {
	/// rrsets the GET endpoint returns.
	rrsets: serde_json::Value,
	/// Captured PUT bodies.
	puts: Vec<String>,
	/// Last Authorization header seen.
	auth: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

async fn rrsets(
	State(state): State<Shared>,
	method: axum::http::Method,
	headers: axum::http::HeaderMap,
	body: String,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	if method == axum::http::Method::PUT {
		s.puts.push(body);
		axum::Json(serde_json::json!([]))
	} else {
		axum::Json(s.rrsets.clone())
	}
}

async fn mock(rrsets_json: serde_json::Value) -> (DesecProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		rrsets: rrsets_json,
		..Default::default()
	}));
	let app = Router::new()
		.route("/domains/{zone}/rrsets/", get(rrsets).put(rrsets))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DesecProvider::new(ScopedSecret::new("example.org", "tok"))
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
async fn upsert_puts_quoted_txt_with_correct_subname() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.puts.len(), 1);
	let body = &s.puts[0];
	assert!(body.contains("\"subname\":\"_dmarc\""), "{body}");
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
	// TXT content is quoted (escaped within the JSON string).
	assert!(body.contains("v=DMARC1; p=none"), "{body}");
	// Token auth, not bearer.
	assert_eq!(s.auth.as_deref(), Some("Token tok"));
}

#[tokio::test]
async fn apex_record_uses_empty_subname() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"subname\":\"\""), "{body}");
}

#[tokio::test]
async fn delete_puts_empty_records() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"records\":[]"), "{body}");
}

#[tokio::test]
async fn list_parses_rrsets_and_unquotes_txt() {
	let rrsets = serde_json::json!([
		{ "subname": "", "type": "TXT", "ttl": 3600, "records": ["\"v=spf1 -all\""] },
		{ "subname": "_dmarc", "type": "TXT", "ttl": 3600, "records": ["\"v=DMARC1; p=none\""] }
	]);
	let (provider, _state) = mock(rrsets).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 2);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(records.iter().any(|r| r.name == "_dmarc.example.org"));
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().puts.is_empty());
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, _state) = mock(serde_json::json!([])).await;
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
