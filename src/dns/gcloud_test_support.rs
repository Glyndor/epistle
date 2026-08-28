//! Test harness for the Google Cloud DNS provider: a generated RSA keypair,
//! an in-process axum mock of the OAuth2 token endpoint and the DNS API, and
//! the helpers the tests in `gcloud_tests.rs` share. Split out so neither file
//! crosses the line limit; the mock is most of the volume.

use std::sync::{Arc, Mutex, OnceLock};

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::signature::UnparsedPublicKey;
use serde_json::Value;
use tempfile::NamedTempFile;

use super::*;

/// One RSA-2048 keypair, generated on demand by `openssl genpkey`. Cached
/// across tests so the `openssl` invocation runs at most once per process.
pub(super) struct TestKey {
	pub(super) pem: String,
	/// PKCS#1 RSAPublicKey (DER) — what `ring` wants for verification.
	/// (`ring`'s RSA verifier expects the raw `RSAPublicKey` SEQUENCE, not the
	/// SPKI wrapper that `-pubout` produces by default.)
	pub(super) pub_der: Vec<u8>,
}

pub(super) static KEY: OnceLock<TestKey> = OnceLock::new();

pub(super) fn test_key() -> &'static TestKey {
	KEY.get_or_init(generate_key)
}

pub(super) fn generate_key() -> TestKey {
	let pem_file = NamedTempFile::new().expect("temp pem");
	let der_file = NamedTempFile::new().expect("temp der");
	let pem_path = pem_file.path();
	let der_path = der_file.path();
	let status = std::process::Command::new("openssl")
		.args([
			"genpkey",
			"-algorithm",
			"RSA",
			"-pkeyopt",
			"rsa_keygen_bits:2048",
			"-out",
		])
		.arg(pem_path)
		.status()
		.expect("openssl genpkey");
	assert!(status.success(), "openssl genpkey failed");
	let status = std::process::Command::new("openssl")
		.args(["rsa", "-in"])
		.arg(pem_path)
		.args(["-RSAPublicKey_out", "-outform", "DER", "-out"])
		.arg(der_path)
		.status()
		.expect("openssl rsa -RSAPublicKey_out");
	assert!(status.success(), "openssl rsa failed");
	let pem = std::fs::read_to_string(pem_path).expect("read pem");
	let pub_der = std::fs::read(der_path).expect("read der");
	let pem = pem.trim_end().to_string();
	TestKey { pem, pub_der }
}

#[derive(Default)]
pub(super) struct MockState {
	/// Rrsets the GET endpoint returns. Mutated between tests to exercise the
	/// replace-in-place path.
	pub(super) rrsets: serde_json::Value,
	/// Bodies of every `POST /changes` request, in arrival order.
	pub(super) changes: Vec<String>,
	/// The JWT presented to `/token` (the assertion form field).
	pub(super) last_assertion: Option<String>,
	/// Bearer token the provider must send on every DNS API request.
	pub(super) expected_bearer: Option<String>,
	/// All Authorization headers captured on DNS endpoints.
	pub(super) bearers: Vec<String>,
	/// Rrsets now considered live (used to compute whether a change is valid).
	pub(super) live_rrsets: Vec<Rrset>,
}

pub(super) type Shared = Arc<Mutex<MockState>>;

/// Decode `application/x-www-form-urlencoded` body without pulling in a new
/// dep: pull the `assertion` and `grant_type` fields by name.
pub(super) fn parse_form(body: &str) -> (Option<String>, Option<String>) {
	let mut assertion = None;
	let mut grant_type = None;
	for pair in body.split('&') {
		let Some((k, v)) = pair.split_once('=') else {
			continue;
		};
		let Ok(decoded) = urldecode(v) else {
			continue;
		};
		match k {
			"assertion" => assertion = Some(decoded),
			"grant_type" => grant_type = Some(decoded),
			_ => {}
		}
	}
	(assertion, grant_type)
}

pub(super) fn urldecode(input: &str) -> Result<String, ()> {
	let bytes = input.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		match bytes[i] {
			b'+' => {
				out.push(b' ');
				i += 1;
			}
			b'%' if i + 2 < bytes.len() => {
				let hi = hex_digit(bytes[i + 1])?;
				let lo = hex_digit(bytes[i + 2])?;
				out.push((hi << 4) | lo);
				i += 3;
			}
			b => {
				out.push(b);
				i += 1;
			}
		}
	}
	String::from_utf8(out).map_err(|_| ())
}

pub(super) fn hex_digit(b: u8) -> Result<u8, ()> {
	match b {
		b'0'..=b'9' => Ok(b - b'0'),
		b'a'..=b'f' => Ok(b - b'a' + 10),
		b'A'..=b'F' => Ok(b - b'A' + 10),
		_ => Err(()),
	}
}

/// POST /token — verify the JWT, mint a fake access token.
pub(super) async fn token(
	State(state): State<Shared>,
	body: String,
) -> Result<axum::Json<Value>, (axum::http::StatusCode, String)> {
	let (assertion, grant_type) = parse_form(&body);
	let Some(assertion) = assertion else {
		return Err((
			axum::http::StatusCode::BAD_REQUEST,
			"missing assertion".into(),
		));
	};
	if grant_type.as_deref() != Some("urn:ietf:params:oauth:grant-type:jwt-bearer") {
		return Err((
			axum::http::StatusCode::BAD_REQUEST,
			"wrong grant_type".into(),
		));
	}
	// Verify the JWT against the test RSA public key. We deliberately do NOT
	// verify iss/aud/exp here — that is the provider's job, not the mock's —
	// but we DO verify alg=RS256 and the signature, so a bad signing key
	// surfaces as a 401 here, not as a "test passed".
	let jwt = assertion.clone();
	let mut parts = jwt.split('.');
	let (header_b64, payload_b64, sig_b64) =
		match (parts.next(), parts.next(), parts.next(), parts.next()) {
			(Some(h), Some(p), Some(s), None) => (h, p, s),
			_ => return Err((axum::http::StatusCode::BAD_REQUEST, "bad jwt shape".into())),
		};
	let header: Value = serde_json::from_slice(
		&B64URL
			.decode(header_b64)
			.map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("{e}")))?,
	)
	.map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("{e}")))?;
	if header.get("alg").and_then(Value::as_str) != Some("RS256") {
		return Err((axum::http::StatusCode::UNAUTHORIZED, "alg != RS256".into()));
	}
	let sig = B64URL
		.decode(sig_b64)
		.map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("{e}")))?;
	let signing_input = format!("{header_b64}.{payload_b64}");
	let key = test_key();
	if let Err(e) =
		UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, &key.pub_der)
			.verify(signing_input.as_bytes(), &sig)
	{
		return Err((
			axum::http::StatusCode::UNAUTHORIZED,
			format!("bad signature: {e:?}"),
		));
	}
	let mut s = state.lock().unwrap();
	s.last_assertion = Some(jwt);
	// Mint a fresh-looking token so cache-hit assertions stay stable.
	let token = format!("ya29.test.{}", s.changes.len());
	s.expected_bearer = Some(token.clone());
	Ok(axum::Json(serde_json::json!({
		"access_token": token,
		"expires_in": 3600,
		"token_type": "Bearer",
	})))
}

/// GET /dns/v1/projects/{p}/managedZones[?dnsName=…] — list matching zones.
pub(super) async fn list_zones(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
) -> Result<axum::Json<Value>, axum::http::StatusCode> {
	let auth = headers
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");
	if !auth.starts_with("Bearer ") {
		return Err(axum::http::StatusCode::UNAUTHORIZED);
	}
	let mut s = state.lock().unwrap();
	s.bearers.push(auth.to_string());
	Ok(axum::Json(serde_json::json!({
		"managedZones": [
			{ "name": "example-org", "dnsName": "example.org." }
		]
	})))
}

/// GET /dns/v1/projects/{p}/managedZones/{z}/rrsets — return the current set.
pub(super) async fn list_rrsets(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
) -> Result<axum::Json<Value>, axum::http::StatusCode> {
	let auth = headers
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");
	if !auth.starts_with("Bearer ") {
		return Err(axum::http::StatusCode::UNAUTHORIZED);
	}
	let mut s = state.lock().unwrap();
	s.bearers.push(auth.to_string());
	let value = serde_json::json!({ "rrsets": s.live_rrsets });
	Ok(axum::Json(value))
}

/// POST /dns/v1/projects/{p}/managedZones/{z}/changes — apply additions/deletions.
pub(super) async fn post_change(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
	body: String,
) -> Result<axum::Json<Value>, axum::http::StatusCode> {
	let auth = headers
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");
	if !auth.starts_with("Bearer ") {
		return Err(axum::http::StatusCode::UNAUTHORIZED);
	}
	let mut s = state.lock().unwrap();
	s.bearers.push(auth.to_string());
	let parsed: Value =
		serde_json::from_str(&body).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	// Apply deletions first, then additions.
	if let Some(dels) = parsed.get("deletions").and_then(Value::as_array) {
		for d in dels {
			let name = d["name"].as_str().unwrap_or("").to_string();
			let kind = d["type"].as_str().unwrap_or("").to_string();
			s.live_rrsets
				.retain(|r| !(r.name == name && r.kind == kind));
		}
	}
	if let Some(adds) = parsed.get("additions").and_then(Value::as_array) {
		for a in adds {
			s.live_rrsets.push(Rrset {
				name: a["name"].as_str().unwrap().to_string(),
				kind: a["type"].as_str().unwrap().to_string(),
				ttl: a["ttl"].as_u64().unwrap_or(0) as u32,
				rrdatas: a["rrdatas"]
					.as_array()
					.map(|v| {
						v.iter()
							.filter_map(Value::as_str)
							.map(str::to_string)
							.collect()
					})
					.unwrap_or_default(),
			});
		}
	}
	s.changes.push(body);
	Ok(axum::Json(serde_json::json!({
		"id": "change-1",
		"status": "done",
		"startTime": "2026-01-01T00:00:00Z",
	})))
}

/// Drop-in extension handler for routes that take any query string.
pub(super) fn build_router(state: Shared) -> Router {
	Router::new()
		.route("/token", post(token))
		.route("/dns/v1/projects/{project}/managedZones", get(list_zones))
		.route(
			"/dns/v1/projects/{project}/managedZones/{zone}",
			get(list_zones),
		)
		.route(
			"/dns/v1/projects/{project}/managedZones/{zone}/rrsets",
			get(list_rrsets),
		)
		.route(
			"/dns/v1/projects/{project}/managedZones/{zone}/changes",
			post(post_change),
		)
		.with_state(state)
}

pub(super) async fn start_mock(initial_rrsets: Vec<Rrset>) -> (String, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		live_rrsets: initial_rrsets.clone(),
		rrsets: serde_json::json!({ "rrsets": initial_rrsets }),
		..Default::default()
	}));
	let app = build_router(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	(format!("http://{addr}"), state)
}

pub(super) fn provider_for(base: &str) -> GcloudProvider {
	let account = ServiceAccount {
		client_email: "sa@example.iam.gserviceaccount.com".into(),
		private_key: test_key().pem.clone(),
		project_id: "proj".into(),
	};
	GcloudProvider::new(ScopedSecret::new("example.org", ""), account)
		.with_token_base(base.to_string())
		.with_dns_base(base.to_string())
}

pub(super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
}
