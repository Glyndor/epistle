//! The challenge of an S256 flow is the digest of the verifier, so it has one
//! exact shape: 43 characters of the base64url alphabet (RFC 7636 §4.2).
//! Anything else is refused before it is stored.
use super::super::base::{keys, state_with_authz};
use crate::api::tests::hostile_wire::{Peer, supervised};
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

/// A valid S256 challenge: 43 characters of the base64url alphabet.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[tokio::test]
async fn a_challenge_that_is_not_a_digest_is_refused_on_wire() {
	if supervised(
		module_path!(),
		"a_challenge_that_is_not_a_digest_is_refused_on_wire",
	) {
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let peer = Peer::start(crate::api::router(state.clone())).await;
	for challenge in [
		// Too short and too long: the digest of a verifier is 43 characters.
		"a".repeat(42),
		"a".repeat(44),
		// Characters outside the base64url alphabet.
		format!("{}=", "a".repeat(42)),
		format!("{}+", "a".repeat(42)),
		format!("{}/", "a".repeat(42)),
		"a".repeat(41) + " ",
	] {
		let (status, body) = peer
			.json(
				"/oauth/authorize",
				json!({
					"client_id": "cli", "login": "alice@example.org",
					"password": crate::test_support::fixtures::password(),
					"code_challenge_method": "S256", "code_challenge": challenge
				}),
			)
			.await;
		assert_eq!(
			status,
			StatusCode::BAD_REQUEST,
			"challenge {challenge:?}: {body}"
		);
		assert_eq!(body["error"], "invalid_request", "challenge {challenge:?}");
		assert!(body.get("code").is_none());
	}
	assert!(
		state.authz().unwrap().codes.lock().unwrap().is_empty(),
		"no refused challenge was stored"
	);
	// The exact shape is accepted.
	let (status, body) = peer
		.json(
			"/oauth/authorize",
			json!({
				"client_id": "cli", "login": "alice@example.org",
				"password": crate::test_support::fixtures::password(),
				"code_challenge_method": "S256", "code_challenge": CHALLENGE
			}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(body.get("code").is_some(), "{body}");
	peer.healthy().await;
}

#[tokio::test]
async fn a_two_mebibyte_challenge_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let app = crate::api::router(state.clone());
	let body = format!(
		"client_id=cli&code_challenge={}&code_challenge_method=S256\
		 &login=alice@example.org&password={}",
		"a".repeat(2 * 1024 * 1024),
		crate::test_support::fixtures::password()
	);
	let mut request = axum::http::Request::builder()
		.method("POST")
		.uri("/oauth/authorize")
		.header(
			axum::http::header::CONTENT_TYPE,
			"application/x-www-form-urlencoded",
		)
		.body(axum::body::Body::from(body))
		.expect("request");
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			[198, 51, 100, 1],
			4000,
		))));
	let response = app.oneshot(request).await.expect("response");
	let status = response.status();
	// The body is over the limit the listener reads, so it never reaches the
	// endpoint; either way no code is issued and nothing is stored.
	assert_eq!(
		status,
		StatusCode::PAYLOAD_TOO_LARGE,
		"the body is over the limit the listener reads"
	);
	assert!(
		state.authz().unwrap().codes.lock().unwrap().is_empty(),
		"the two megabytes were not stored"
	);
}

#[tokio::test]
async fn a_megabyte_challenge_is_refused_before_it_is_stored() {
	if supervised(
		module_path!(),
		"a_megabyte_challenge_is_refused_before_it_is_stored",
	) {
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let peer = Peer::start(crate::api::router(state.clone())).await;
	// A megabyte of challenge still fits in the body the listener accepts,
	// so the endpoint itself has to refuse it.
	let (status, body) = peer
		.json(
			"/oauth/authorize",
			json!({
				"client_id": "cli", "login": "alice@example.org",
				"password": crate::test_support::fixtures::password(),
				"code_challenge_method": "S256", "code_challenge": "a".repeat(1024 * 1024)
			}),
		)
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"], "invalid_request");
	assert!(body.get("code").is_none());
	assert!(
		state.authz().unwrap().codes.lock().unwrap().is_empty(),
		"the megabyte was not stored"
	);
	peer.healthy().await;
}
