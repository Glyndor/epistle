//! Tests for the Google Cloud DNS provider against an in-process axum mock.
//!
//! The mock serves both the OAuth token endpoint (`POST /token`) and the Cloud
//! DNS API (`/dns/v1/...`) on the same address, mirroring how a real Google
//! frontend routes both. The token handler verifies the JWT's RS256 signature
//! against the test-generated RSA public key, so the test fails closed if the
//! signing code ever drifts.
//!
//! `ring` does not expose RSA key generation, so the per-test RSA pair is
//! minted with the `openssl` CLI on first use and cached in a static. The PEM
//! and DER never leave the test process — no real or pre-baked key material
//! sits in the tree.

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
struct TestKey {
	pem: String,
	/// PKCS#1 RSAPublicKey (DER) — what `ring` wants for verification.
	/// (`ring`'s RSA verifier expects the raw `RSAPublicKey` SEQUENCE, not the
	/// SPKI wrapper that `-pubout` produces by default.)
	pub_der: Vec<u8>,
}

static KEY: OnceLock<TestKey> = OnceLock::new();

fn test_key() -> &'static TestKey {
	KEY.get_or_init(generate_key)
}

fn generate_key() -> TestKey {
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
struct MockState {
	/// Rrsets the GET endpoint returns. Mutated between tests to exercise the
	/// replace-in-place path.
	rrsets: serde_json::Value,
	/// Bodies of every `POST /changes` request, in arrival order.
	changes: Vec<String>,
	/// The JWT presented to `/token` (the assertion form field).
	last_assertion: Option<String>,
	/// Bearer token the provider must send on every DNS API request.
	expected_bearer: Option<String>,
	/// All Authorization headers captured on DNS endpoints.
	bearers: Vec<String>,
	/// Rrsets now considered live (used to compute whether a change is valid).
	live_rrsets: Vec<Rrset>,
}

type Shared = Arc<Mutex<MockState>>;

/// Decode `application/x-www-form-urlencoded` body without pulling in a new
/// dep: pull the `assertion` and `grant_type` fields by name.
fn parse_form(body: &str) -> (Option<String>, Option<String>) {
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

fn urldecode(input: &str) -> Result<String, ()> {
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

fn hex_digit(b: u8) -> Result<u8, ()> {
	match b {
		b'0'..=b'9' => Ok(b - b'0'),
		b'a'..=b'f' => Ok(b - b'a' + 10),
		b'A'..=b'F' => Ok(b - b'A' + 10),
		_ => Err(()),
	}
}

/// POST /token — verify the JWT, mint a fake access token.
async fn token(
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
async fn list_zones(
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
async fn list_rrsets(
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
async fn post_change(
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
fn build_router(state: Shared) -> Router {
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

async fn start_mock(initial_rrsets: Vec<Rrset>) -> (String, Shared) {
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

fn provider_for(base: &str) -> GcloudProvider {
	let account = ServiceAccount {
		client_email: "sa@example.iam.gserviceaccount.com".into(),
		private_key: test_key().pem.clone(),
		project_id: "proj".into(),
	};
	GcloudProvider::new(ScopedSecret::new("example.org", ""), account)
		.with_token_base(base.to_string())
		.with_dns_base(base.to_string())
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
async fn upsert_under_subdomain_posts_signed_change_with_quoted_txt() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body = s.changes.last().expect("a change body");
	assert!(body.contains("\"name\":\"_dmarc.example.org.\""), "{body}");
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
	// TXT rrdatas carry a quoted, escaped string.
	assert!(
		body.contains("\"rrdatas\":[\"\\\"v=DMARC1; p=none\\\"\"]"),
		"{body}"
	);
	// The provider obtained a bearer (from `/token`) and reused it.
	assert!(s.bearers.iter().all(|b| b.starts_with("Bearer ya29.test.")));
	// And the JWT was verified by `/token` — the assertion is captured here.
	assert!(
		s.last_assertion.as_deref().unwrap_or("").split('.').count() == 3,
		"last_assertion must be a JWT"
	);
	// The header declares the algorithm we signed with.
	let assertion = s.last_assertion.as_deref().unwrap();
	let header_b64 = assertion.split('.').next().unwrap();
	let header: Value = serde_json::from_slice(&B64URL.decode(header_b64).unwrap()).unwrap();
	assert_eq!(header["alg"], "RS256");
	assert_eq!(header["typ"], "JWT");
}

#[tokio::test]
async fn upsert_at_apex_uses_trailing_dot_zone_name() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().unwrap().clone();
	assert!(body.contains("\"name\":\"example.org.\""), "{body}");
	assert!(body.contains("\"additions\":[{"), "{body}");
	assert!(body.contains("\"deletions\":[]"), "{body}");
}

#[tokio::test]
async fn upsert_existing_replaces_with_deletions_plus_additions() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	// Seed a pre-existing rrset so the next upsert must replace it.
	let initial = vec![Rrset {
		name: "_dmarc.example.org.".into(),
		kind: "TXT".into(),
		ttl: 300,
		rrdatas: vec!["\"old\"".into()],
	}];
	{
		let mut s = state.lock().unwrap();
		s.live_rrsets = initial.clone();
		s.rrsets = serde_json::json!({ "rrsets": initial });
	}
	provider
		.upsert("example.org", txt("_dmarc.example.org", "new-value"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().unwrap().clone();
	// One change carries both the old (deletion) and the new (addition).
	assert!(body.contains("\"deletions\":[{"), "{body}");
	assert!(body.contains("\"rrdatas\":[\"\\\"old\\\"\"]"), "{body}");
	assert!(body.contains("\"additions\":[{"), "{body}");
	assert!(
		body.contains("\"rrdatas\":[\"\\\"new-value\\\"\"]"),
		"{body}"
	);
	// Calling upsert again with the same value must NOT submit a no-op change
	// (avoids the "two TXT for the same name" foot-gun).
	let before = state.lock().unwrap().changes.len();
	provider
		.upsert("example.org", txt("_dmarc.example.org", "new-value"))
		.await
		.expect("upsert");
	assert_eq!(
		state.lock().unwrap().changes.len(),
		before,
		"identical upsert must not submit another change"
	);
}

#[tokio::test]
async fn delete_is_idempotent_when_rrset_is_absent() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete absent");
	assert!(
		state.lock().unwrap().changes.is_empty(),
		"no change should be submitted for an already-absent rrset"
	);
	// Now seed an rrset and verify a real delete fires.
	let initial = vec![Rrset {
		name: "_dmarc.example.org.".into(),
		kind: "TXT".into(),
		ttl: 300,
		rrdatas: vec!["\"old\"".into()],
	}];
	{
		let mut s = state.lock().unwrap();
		s.live_rrsets = initial;
	}
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete present");
	let body = state.lock().unwrap().changes.last().unwrap().clone();
	assert!(body.contains("\"deletions\":[{"), "{body}");
	assert!(body.contains("\"additions\":[]"), "{body}");
}

#[tokio::test]
async fn list_parses_rrsets_unquotes_txt_and_returns_fqdns() {
	let initial = vec![
		Rrset {
			name: "example.org.".into(),
			kind: "TXT".into(),
			ttl: 3600,
			rrdatas: vec!["\"v=spf1 -all\"".into()],
		},
		Rrset {
			name: "_dmarc.example.org.".into(),
			kind: "TXT".into(),
			ttl: 3600,
			rrdatas: vec!["\"v=DMARC1; p=none\"".into()],
		},
		Rrset {
			name: "mail.example.org.".into(),
			kind: "A".into(),
			ttl: 300,
			rrdatas: vec!["203.0.113.10".into()],
		},
		// A record under a different zone must be filtered out.
		Rrset {
			name: "mail.other.org.".into(),
			kind: "A".into(),
			ttl: 300,
			rrdatas: vec!["203.0.113.11".into()],
		},
	];
	let (base, _state) = start_mock(initial).await;
	let provider = provider_for(&base);
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 3);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org" && r.kind == RecordKind::Txt)
		.expect("apex TXT");
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(
		records
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.kind == RecordKind::Txt)
	);
	assert!(
		records
			.iter()
			.any(|r| r.name == "mail.example.org" && r.kind == RecordKind::A)
	);
	assert!(!records.iter().any(|r| r.name.ends_with("other.org")));
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	let s = state.lock().unwrap();
	assert!(s.changes.is_empty(), "no DNS API call must be made");
	// The token endpoint was also not contacted: there is no JWT to verify.
	assert!(s.last_assertion.is_none());
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (base, _state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
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

/// PEM round-trip: a valid PKCS#8 PEM decodes to a non-empty DER blob.
#[test]
fn pem_decoder_round_trips_a_pkcs8_block() {
	let key = test_key();
	assert!(key.pem.contains("BEGIN PRIVATE KEY"));
	let der = pem_to_pkcs8(&key.pem).expect("decode pem");
	assert!(!der.is_empty());
}

/// A malformed PEM returns `None`, not a panic.
#[test]
fn pem_decoder_rejects_garbage() {
	assert!(pem_to_pkcs8("not a pem at all").is_none());
	assert!(
		pem_to_pkcs8("-----BEGIN PRIVATE KEY-----\n!!!notbase64!!!\n-----END PRIVATE KEY-----")
			.is_none()
	);
}

/// RS256 sign+verify round-trip: a freshly signed token verifies against the
/// same test public key the mock uses.
#[test]
fn rs256_sign_then_verify() {
	let claims = serde_json::json!({
		"iss": "sa@example.iam.gserviceaccount.com",
		"scope": DNS_SCOPE,
		"aud": TOKEN_AUDIENCE,
		"iat": 1_000_000,
		"exp": 2_000_000,
	});
	let token = sign_rs256(&test_key().pem, &claims).expect("sign");
	let mut parts = token.split('.');
	let (h, p, s) = (
		parts.next().unwrap(),
		parts.next().unwrap(),
		parts.next().unwrap(),
	);
	assert_eq!(parts.next(), None);
	let header: Value = serde_json::from_slice(&B64URL.decode(h).unwrap()).unwrap();
	assert_eq!(header["alg"], "RS256");
	assert_eq!(header["typ"], "JWT");
	let payload: Value = serde_json::from_slice(&B64URL.decode(p).unwrap()).unwrap();
	assert_eq!(payload["iss"], "sa@example.iam.gserviceaccount.com");
	let sig2 = B64URL.decode(s).unwrap();
	UnparsedPublicKey::new(
		&ring::signature::RSA_PKCS1_2048_8192_SHA256,
		&test_key().pub_der,
	)
	.verify(format!("{h}.{p}").as_bytes(), &sig2)
	.expect("verify");
}
