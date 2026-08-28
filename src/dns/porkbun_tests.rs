//! Tests for the Porkbun provider against an in-process axum mock. The mock
//! answers with the JSON shapes documented at <https://porkbun.com/llms/dns>
//! and in the OpenAPI spec at <https://porkbun.com/api/json/v3/spec>: `id`,
//! `ttl` and `prio` come back as strings, `name` as a fully-qualified name, and
//! every reply carries a `status` field.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::post;

/// One captured request: the path it hit and the JSON body it carried.
struct Call {
	path: String,
	body: serde_json::Value,
}

#[derive(Default)]
struct MockState {
	/// Records `POST /dns/retrieve/{zone}` reports.
	records: serde_json::Value,
	/// When set, every endpoint answers this instead (with `200 OK`).
	fail: Option<serde_json::Value>,
	/// Every request seen, in order.
	calls: Vec<Call>,
	/// Header names seen on the last request, lowercased.
	headers: Vec<String>,
}

impl MockState {
	/// The paths hit so far.
	fn paths(&self) -> Vec<&str> {
		self.calls.iter().map(|c| c.path.as_str()).collect()
	}

	/// The body of the single call to `path`.
	fn body(&self, path: &str) -> serde_json::Value {
		let mut hits = self.calls.iter().filter(|c| c.path == path);
		let call = hits.next().unwrap_or_else(|| panic!("no call to {path}"));
		assert!(hits.next().is_none(), "more than one call to {path}");
		call.body.clone()
	}
}

type Shared = Arc<Mutex<MockState>>;

async fn hit(
	State(state): State<Shared>,
	uri: axum::http::Uri,
	headers: axum::http::HeaderMap,
	body: String,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	let path = uri.path().to_string();
	s.headers = headers
		.keys()
		.map(|k| k.as_str().to_ascii_lowercase())
		.collect();
	s.calls.push(Call {
		path: path.clone(),
		body: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
	});
	if let Some(fail) = s.fail.clone() {
		return axum::Json(fail);
	}
	if path.starts_with("/dns/retrieve/") {
		return axum::Json(serde_json::json!({
			"status": "SUCCESS",
			"cloudflare": "disabled",
			"records": s.records.clone(),
		}));
	}
	if path.starts_with("/dns/create/") {
		return axum::Json(serde_json::json!({ "status": "SUCCESS", "id": "106926652" }));
	}
	axum::Json(serde_json::json!({ "status": "SUCCESS" }))
}

/// Start the mock and return (provider pointed at it, shared state).
async fn mock(records: serde_json::Value) -> (PorkbunProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		records,
		..Default::default()
	}));
	let app = Router::new()
		.route("/dns/retrieve/{zone}", post(hit))
		.route("/dns/create/{zone}", post(hit))
		.route("/dns/edit/{zone}/{id}", post(hit))
		.route("/dns/delete/{zone}/{id}", post(hit))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider =
		PorkbunProvider::new(ScopedSecret::new("example.org", "sk1_secret"), "pk1_apikey")
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

/// One record as `POST /dns/retrieve/{zone}` returns it.
fn stored(id: &str, name: &str, kind: &str, content: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id,
		"name": name,
		"type": kind,
		"content": content,
		"ttl": "600",
		"prio": "0",
		"notes": "",
	})
}

#[tokio::test]
async fn upsert_creates_txt_with_the_relative_name_and_body_credentials() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	// Retrieve first (to find an existing record), then create.
	assert_eq!(
		s.paths(),
		vec!["/dns/retrieve/example.org", "/dns/create/example.org"]
	);
	let body = s.body("/dns/create/example.org");
	assert_eq!(body["name"], "_dmarc");
	assert_eq!(body["type"], "TXT");
	assert_eq!(body["content"], "v=DMARC1; p=none");
	assert_eq!(body["ttl"], 3600);
	// Porkbun authenticates from the body, not a header.
	assert_eq!(body["apikey"], "pk1_apikey");
	assert_eq!(body["secretapikey"], "sk1_secret");
	for header in ["authorization", "x-api-key", "x-secret-api-key"] {
		assert!(!s.headers.contains(&header.to_string()), "{header} sent");
	}
}

#[tokio::test]
async fn apex_record_uses_a_blank_name() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 mx -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().body("/dns/create/example.org");
	assert_eq!(body["name"], "");
}

#[tokio::test]
async fn upsert_edits_the_existing_record_and_drops_a_duplicate() {
	let records = serde_json::json!([
		stored("106926652", "_dmarc.example.org", "TXT", "v=DMARC1; p=none"),
		stored(
			"106926653",
			"_dmarc.example.org",
			"TXT",
			"v=DMARC1; p=reject"
		),
		stored("106926654", "example.org", "TXT", "v=spf1 mx -all"),
	]);
	let (provider, state) = mock(records).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=quarantine"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(
		s.paths(),
		vec![
			"/dns/retrieve/example.org",
			"/dns/edit/example.org/106926652",
			"/dns/delete/example.org/106926653",
		]
	);
	// Never a create: an upsert replaces, it does not add a third TXT.
	assert!(
		!s.paths().iter().any(|p| p.starts_with("/dns/create/")),
		"{:?}",
		s.paths()
	);
	let body = s.body("/dns/edit/example.org/106926652");
	assert_eq!(body["content"], "v=DMARC1; p=quarantine");
	assert_eq!(body["name"], "_dmarc");
}

#[tokio::test]
async fn deleting_an_absent_record_succeeds() {
	let (provider, state) = mock(serde_json::json!([stored(
		"106926654",
		"example.org",
		"TXT",
		"v=spf1 mx -all"
	)]))
	.await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("delete is idempotent");
	let s = state.lock().unwrap();
	assert_eq!(s.paths(), vec!["/dns/retrieve/example.org"]);
}

#[tokio::test]
async fn delete_removes_the_matching_record_by_id() {
	let (provider, state) = mock(serde_json::json!([stored(
		"106926652",
		"_dmarc.example.org",
		"TXT",
		"v=DMARC1; p=none"
	)]))
	.await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(
		s.paths(),
		vec![
			"/dns/retrieve/example.org",
			"/dns/delete/example.org/106926652"
		]
	);
	let body = s.body("/dns/delete/example.org/106926652");
	assert_eq!(body["apikey"], "pk1_apikey");
	assert_eq!(body["secretapikey"], "sk1_secret");
}

#[tokio::test]
async fn list_returns_fqdn_names_and_unquoted_values() {
	// Porkbun echoes the stored content verbatim, so a zone imported with
	// literal quotes around a TXT value keeps them.
	let records = serde_json::json!([
		stored("106926652", "example.org", "TXT", "\"v=spf1 mx -all\""),
		stored("106926653", "_dmarc.example.org", "TXT", "v=DMARC1; p=none"),
		stored("106926654", "mail.example.org", "A", "203.0.113.10"),
	]);
	let (provider, _state) = mock(records).await;
	let listed = provider.list("example.org").await.expect("list");
	assert_eq!(listed.len(), 3);
	let apex = listed
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.value, "v=spf1 mx -all");
	assert_eq!(apex.kind, RecordKind::Txt);
	assert_eq!(apex.ttl, 600);
	assert!(
		listed
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.value == "v=DMARC1; p=none")
	);
	let host = listed
		.iter()
		.find(|r| r.name == "mail.example.org")
		.expect("host");
	assert_eq!(host.kind, RecordKind::A);
	assert_eq!(host.value, "203.0.113.10");
}

#[tokio::test]
async fn record_outside_the_zone_is_rejected_without_network() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let result = provider
		.upsert(
			"example.org",
			txt("_dmarc.other.example", "v=DMARC1; p=none"),
		)
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, state) = mock(serde_json::json!([])).await;
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
	assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn error_status_with_http_200_is_a_failure() {
	let (provider, state) = mock(serde_json::json!([])).await;
	state.lock().unwrap().fail = Some(serde_json::json!({
		"status": "ERROR",
		"message": "Invalid domain.",
		"code": "INVALID_DOMAIN",
	}));
	assert_eq!(
		provider
			.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
			.await,
		Err(ProviderError::Remote("Invalid domain.".to_string()))
	);
}

#[tokio::test]
async fn rejected_credentials_map_to_an_auth_error() {
	let (provider, state) = mock(serde_json::json!([])).await;
	state.lock().unwrap().fail = Some(serde_json::json!({
		"status": "ERROR",
		"message": "Invalid API key.",
		"code": "INVALID_API_KEYS_001",
	}));
	assert_eq!(provider.list("example.org").await, Err(ProviderError::Auth));
}
