//! Tests for the built-in OAuth 2.0 authorization server (device flow + PKCE).
//!
//! Every test exercises the public router, drives the grants end to end, and
//! confirms the issued token verifies through the real [`OauthVerifier`] built
//! from the matching public key — plus the failure paths (bad creds, wrong
//! verifier, plain method, one-time-use, expiry).

use crate::api::{ApiState, router};
use crate::oauth::OauthVerifier;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use tower::ServiceExt;

const ISSUER: &str = "https://mail.example";
const AUDIENCE: &str = "mail";
const LOGIN: &str = "alice@example.org";
const PASSWORD: &str = "correct horse battery staple";

/// An ES256 key pair: the base64 PKCS#8 private key for the signer and the
/// base64 public point for the verifier (they are a matching pair).
struct Keys {
	private_b64: String,
	public_b64: String,
}

fn keys() -> Keys {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("gen");
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
		.expect("parse");
	Keys {
		private_b64: B64.encode(pkcs8.as_ref()),
		public_b64: B64.encode(pair.public_key().as_ref()),
	}
}

/// Build an API state with one known account (`alice`, password known) and the
/// authorization server wired to `keys`.
fn state_with_authz(dir: &std::path::Path, keys: &Keys) -> ApiState {
	let spool = crate::storage::FsSpool::open(dir).expect("spool");
	let accounts = vec![crate::config::Account {
		name: "alice".to_string(),
		addresses: vec![LOGIN.to_string()],
		password_hash: Some(crate::smtp::auth::hash_password(PASSWORD).expect("hash")),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("store"),
	);
	let token_hash = {
		let digest = ring::digest::digest(&ring::digest::SHA256, b"api-token");
		let hex = digest.as_ref().iter().fold(String::new(), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
		format!("sha256:{hex}")
	};
	let authz = super::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).expect("authz");
	ApiState::new(
		&token_hash,
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store,
		spool,
	)
	.with_authz(authz)
}

/// POST a form body and return `(status, json)`.
async fn post_form(app: &axum::Router, path: &str, form: &str) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.method("POST")
		.uri(path)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.body(Body::from(form.to_string()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("bytes");
	let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(status, json)
}

/// Verify an issued access token through the real verifier built from the public
/// half of the pair, returning the resolved identity (the `sub`).
fn verified_subject(keys: &Keys, token: &str) -> Option<String> {
	let verifier =
		OauthVerifier::new(ISSUER, AUDIENCE, "ES256", &keys.public_b64).expect("verifier");
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	verifier.verify(token, now)
}

#[test]
fn authz_routes_absent_without_signing_key() {
	// With no signing key the grant routes are not mounted (fail closed).
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = ApiState::new(
		"sha256:x",
		dir.path().to_path_buf(),
		Vec::new(),
		store,
		spool,
	);
	assert!(state.authz().is_none());
}

#[tokio::test]
async fn device_flow_pending_then_approved_issues_verifiable_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	// Keep the state so the test can reset the per-grant poll backoff between the
	// (otherwise rate-limited) rapid polls — keeping the test deterministic with
	// no sleeps, while the slow_down behaviour itself is covered separately.
	let state = state_with_authz(dir.path(), &keys);
	let app = router(state.clone());
	let reset_backoff = |code: &str| {
		let authz = state.authz().expect("authz");
		let mut devices = authz.devices.lock().unwrap();
		if let Some(grant) = devices.get_mut(code) {
			grant.next_poll_at = 0;
		}
	};

	// 1. Start the device flow.
	let (status, body) = post_form(&app, "/oauth/device_authorization", "client_id=cli").await;
	assert_eq!(status, StatusCode::OK);
	let device_code = body["device_code"]
		.as_str()
		.expect("device_code")
		.to_string();
	let user_code = body["user_code"].as_str().expect("user_code").to_string();
	assert_eq!(body["interval"], 5);

	// 2. Token before approval → authorization_pending.
	let form = format!(
		"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}"
	);
	let (status, body) = post_form(&app, "/oauth/token", &form).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "authorization_pending");

	// 3. Approve with the correct account credentials.
	let approve = format!(
		"user_code={user_code}&login={LOGIN}&password={}",
		urlenc(PASSWORD)
	);
	let (status, body) = post_form(&app, "/oauth/device/approve", &approve).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["status"], "approved");

	// 4. Token now succeeds with a JWT the real verifier accepts as `sub` = alice.
	reset_backoff(&device_code);
	let (status, body) = post_form(&app, "/oauth/token", &form).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["token_type"], "Bearer");
	let token = body["access_token"].as_str().expect("token");
	assert_eq!(verified_subject(&keys, token).as_deref(), Some("alice"));

	// 5. The device_code is one-time: a second redemption fails.
	let (status, body) = post_form(&app, "/oauth/token", &form).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn device_approve_rejects_bad_credentials_and_unknown_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));

	let (_, body) = post_form(&app, "/oauth/device_authorization", "client_id=cli").await;
	let user_code = body["user_code"].as_str().expect("user_code").to_string();

	// Wrong password → invalid_grant (does not reveal which input was wrong).
	let approve = format!("user_code={user_code}&login={LOGIN}&password=wrong");
	let (status, body) = post_form(&app, "/oauth/device/approve", &approve).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");

	// Unknown user_code with good credentials → the same opaque error.
	let approve = format!(
		"user_code=ZZZZ-ZZZZ&login={LOGIN}&password={}",
		urlenc(PASSWORD)
	);
	let (status, body) = post_form(&app, "/oauth/device/approve", &approve).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn pkce_round_trip_succeeds_and_rejects_failures() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));

	// A verifier and its S256 challenge (RFC 7636).
	let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
	let challenge = B64URL.encode(digest.as_ref());

	// authorize → a one-time code bound to alice + the challenge.
	let auth = format!(
		"client_id=cli&code_challenge={challenge}&code_challenge_method=S256&login={LOGIN}&password={}&state=xyz",
		urlenc(PASSWORD)
	);
	let (status, body) = post_form(&app, "/oauth/authorize", &auth).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["state"], "xyz");
	let code = body["code"].as_str().expect("code").to_string();

	// Wrong verifier → invalid_grant, and the code is consumed by the attempt.
	let bad =
		format!("grant_type=authorization_code&code={code}&code_verifier=wrong-verifier-value");
	let (status, body) = post_form(&app, "/oauth/token", &bad).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");

	// Reusing that (now consumed) code with the correct verifier also fails.
	let good = format!("grant_type=authorization_code&code={code}&code_verifier={verifier}");
	let (status, body) = post_form(&app, "/oauth/token", &good).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");

	// A fresh code with the correct verifier issues a verifiable token.
	let (_, body) = post_form(&app, "/oauth/authorize", &auth).await;
	let code = body["code"].as_str().expect("code").to_string();
	let good = format!("grant_type=authorization_code&code={code}&code_verifier={verifier}");
	let (status, body) = post_form(&app, "/oauth/token", &good).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let token = body["access_token"].as_str().expect("token");
	assert_eq!(verified_subject(&keys, token).as_deref(), Some("alice"));
}

#[tokio::test]
async fn pkce_rejects_plain_method() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	// `plain` (and an absent method) must be rejected: S256 only.
	let auth = format!(
		"client_id=cli&code_challenge=abc&code_challenge_method=plain&login={LOGIN}&password={}",
		urlenc(PASSWORD)
	);
	let (status, body) = post_form(&app, "/oauth/authorize", &auth).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn pkce_authorize_rejects_bad_credentials() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	let auth = "client_id=cli&code_challenge=abc&code_challenge_method=S256&login=alice@example.org&password=nope";
	let (status, body) = post_form(&app, "/oauth/authorize", auth).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "invalid_grant");
}

#[test]
fn expired_device_grant_redeems_as_expired_token() {
	// Drive the store directly to age a grant past its TTL.
	let keys = keys();
	let authz = super::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).expect("authz");
	let device_code = "dc".to_string();
	authz.devices.lock().unwrap().insert(
		device_code.clone(),
		super::DeviceGrant {
			user_code: "AAAA-AAAA".to_string(),
			approved_account: Some("alice".to_string()),
			expires_at: 1, // long past
			next_poll_at: 0,
		},
	);
	let response = super::device::redeem_device_code(&authz, &device_code);
	assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn polling_too_fast_yields_slow_down() {
	// A second poll before next_poll_at elapses gets slow_down (RFC 8628 §3.5).
	let keys = keys();
	let authz = super::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).expect("authz");
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	authz.devices.lock().unwrap().insert(
		"dc".to_string(),
		super::DeviceGrant {
			user_code: "AAAA-AAAA".to_string(),
			approved_account: None,
			expires_at: now + 600,
			next_poll_at: now + 5, // not yet allowed to poll
		},
	);
	let response = super::device::redeem_device_code(&authz, "dc");
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unsupported_grant_type_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	let (status, body) = post_form(&app, "/oauth/token", "grant_type=password").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], "unsupported_grant_type");
}

#[test]
fn authz_build_and_constant_time_eq() {
	let keys = keys();
	assert!(super::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).is_some());
	// Malformed base64 private key → no server (fail closed).
	assert!(super::AuthzServer::new("not base64!!!", ISSUER, AUDIENCE).is_none());
	assert!(super::constant_time_eq(b"abc", b"abc"));
	assert!(!super::constant_time_eq(b"abc", b"abd"));
	assert!(!super::constant_time_eq(b"abc", b"ab"));
}

/// Minimal form-value encoder for the test bodies (spaces only — the test
/// passwords/values contain no other reserved characters).
fn urlenc(value: &str) -> String {
	value.replace(' ', "%20")
}

#[test]
fn parse_fields_decodes_form_escapes_and_json() {
	use axum::body::Bytes;
	use axum::http::HeaderMap;
	// Form body: %XX escapes, `+` as space, a bare key, and a malformed escape
	// that is passed through literally rather than panicking.
	let form = Bytes::from_static(b"login=a%40b.com&password=p+w%25&bare&bad=%zz");
	let fields = super::parse_fields(&HeaderMap::new(), &form);
	assert_eq!(fields.get("login").map(String::as_str), Some("a@b.com"));
	assert_eq!(fields.get("password").map(String::as_str), Some("p w%"));
	assert_eq!(fields.get("bare").map(String::as_str), Some(""));
	assert_eq!(fields.get("bad").map(String::as_str), Some("%zz"));
	// JSON body with the JSON content-type; non-string values are dropped.
	let mut headers = HeaderMap::new();
	headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
	let json = Bytes::from_static(br#"{"login":"x@y.z","password":"s","n":1}"#);
	let fields = super::parse_fields(&headers, &json);
	assert_eq!(fields.get("login").map(String::as_str), Some("x@y.z"));
	assert_eq!(fields.get("password").map(String::as_str), Some("s"));
	assert!(!fields.contains_key("n"));
}

#[tokio::test]
async fn device_approve_accepts_basic_auth() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = keys();
	let app = router(state_with_authz(dir.path(), &keys));
	let (_, body) = post_form(&app, "/oauth/device_authorization", "client_id=cli").await;
	let user_code = body["user_code"].as_str().expect("user_code").to_string();
	// Credentials in an HTTP Basic header instead of body fields.
	let basic = B64.encode(format!("{LOGIN}:{PASSWORD}"));
	let request = Request::builder()
		.method("POST")
		.uri("/oauth/device/approve")
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.header(header::AUTHORIZATION, format!("Basic {basic}"))
		.body(Body::from(format!("user_code={user_code}")))
		.expect("request");
	let response = app.oneshot(request).await.expect("response");
	assert_eq!(response.status(), StatusCode::OK);
}
