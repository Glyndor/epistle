//! Tests for the built-in OAuth 2.0 authorization server (device flow + PKCE).
//!
//! Every test exercises the public router, drives the grants end to end, and
//! confirms the issued token verifies through the real [`OauthVerifier`] built
//! from the matching public key — plus the failure paths (bad creds, wrong
//! verifier, plain method, one-time-use, expiry).

use crate::api::{ApiState, router};
use crate::oauth::OauthVerifier;
use crate::test_fixtures as fixtures;
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

/// An ES256 key pair: the base64 PKCS#8 private key for the signer and the
/// base64 public point for the verifier (they are a matching pair).
pub(in super::super) struct Keys {
	private_b64: String,
	public_b64: String,
}

pub(in super::super) fn keys() -> Keys {
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
pub(in super::super) fn state_with_authz(dir: &std::path::Path, keys: &Keys) -> ApiState {
	let spool = crate::storage::FsSpool::open(dir).expect("spool");
	let accounts = vec![crate::config::Account {
		display_name: None,
		name: "alice".to_string(),
		addresses: vec![LOGIN.to_string()],
		password_hash: Some(crate::smtp::auth::hash_password(fixtures::password()).expect("hash")),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
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
	let authz = super::AuthzServer::new(&keys.private_b64, ISSUER, AUDIENCE).expect("authz");
	ApiState::new_with_optional_token(
		None,
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store,
		spool,
	)
	.with_authz(authz)
}

/// Wire a fixed peer IP into `ConnectInfo` so the OAuth grant handlers
/// (which extract it from there) don't 500 on the test request.
fn attach_peer(request: &mut Request<Body>) {
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			[203, 0, 113, 1],
			12345,
		))));
}

/// POST a form body and return `(status, json)`. Wires the peer IP
/// into `ConnectInfo`; without it the extractor fails and the handler
/// returns 500.
async fn post_form(app: &axum::Router, path: &str, form: &str) -> (StatusCode, serde_json::Value) {
	let mut request = Request::builder()
		.method("POST")
		.uri(path)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.body(Body::from(form.to_string()))
		.expect("request");
	attach_peer(&mut request);
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("bytes");
	let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(status, json)
}

/// Verify an issued access token through the real verifier built from the public
/// half of the pair, returning the account it names.
fn verified_account(keys: &Keys, token: &str) -> Option<String> {
	let verifier = OauthVerifier::new(ISSUER, AUDIENCE, "ES256", &keys.public_b64)
		.expect("verifier")
		.with_own_tokens();
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	verifier
		.verify_identity(token, now)
		.map(|who| who.as_str().to_string())
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
		urlenc(fixtures::password())
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
	assert_eq!(verified_account(&keys, token).as_deref(), Some("alice"));

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
		urlenc(fixtures::password())
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
		urlenc(fixtures::password())
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
	assert_eq!(verified_account(&keys, token).as_deref(), Some("alice"));
}

#[path = "base_extra.rs"]
mod extra;

fn urlenc(value: &str) -> String {
	value.replace(' ', "%20")
}
