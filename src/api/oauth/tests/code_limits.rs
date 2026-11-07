//! `POST /oauth/authorize` hands out codes that live until they are redeemed,
//! so the pool of them is bounded: over the server, per account and per
//! client, and the expired ones are swept when the next code is issued.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::base::{keys, state_with_authz};
use crate::api::router;

/// A valid S256 challenge: 43 characters of the base64url alphabet.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The account the fixture state authenticates as.
const ACCOUNT: &str = "alice";

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

/// A code as the pool holds it, built by hand so a cap can be reached
/// without issuing thousands of them over the wire.
fn code(account: &str, client: Option<(bool, u64)>, expires_at: u64) -> super::AuthCode {
	super::AuthCode {
		account: account.to_string(),
		code_challenge: CHALLENGE.to_string(),
		expires_at,
		redirect_uri: None,
		client,
	}
}

/// The bucket an address is counted in, as the endpoint computes it.
fn bucket(ip: &str) -> Option<(bool, u64)> {
	Some(super::device::client_bucket(ip.parse().expect("ip")))
}

/// Ask for an authorization code and answer `(status, json)`.
async fn authorize(app: &axum::Router, peer: &str) -> (StatusCode, serde_json::Value) {
	let mut request = Request::builder()
		.method("POST")
		.uri("/oauth/authorize")
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.body(Body::from(format!(
			"client_id=cli&code_challenge={CHALLENGE}&code_challenge_method=S256\
			 &login=alice@example.org&password={}",
			crate::test_fixtures::password()
		)))
		.expect("request");
	let peer: std::net::IpAddr = peer.parse().expect("peer");
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			peer, 4000,
		))));
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("bytes");
	let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(status, json)
}

#[tokio::test]
async fn one_account_cannot_hold_more_than_its_share_of_codes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		let mut codes = authz.codes.lock().unwrap();
		for n in 0..super::pkce::MAX_CODES_PER_ACCOUNT {
			codes.insert(format!("old{n}"), code(ACCOUNT, None, now() + 600));
		}
	}
	let app = router(state.clone());
	let (status, body) = authorize(&app, "198.51.100.1").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"], "temporarily_unavailable");
	assert!(body.get("code").is_none(), "{body}");
	assert_eq!(
		authz.codes.lock().unwrap().len(),
		super::pkce::MAX_CODES_PER_ACCOUNT,
		"the refused code was not stored"
	);
}

#[tokio::test]
async fn one_client_cannot_hold_more_than_its_share_of_codes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		// Other accounts, but the same client address.
		let mut codes = authz.codes.lock().unwrap();
		for n in 0..super::pkce::MAX_CODES_PER_CLIENT {
			codes.insert(
				format!("old{n}"),
				code(&format!("bob{n}"), bucket("198.51.100.1"), now() + 600),
			);
		}
	}
	let app = router(state.clone());
	let (status, body) = authorize(&app, "198.51.100.1").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"], "temporarily_unavailable");
	assert_eq!(
		authz.codes.lock().unwrap().len(),
		super::pkce::MAX_CODES_PER_CLIENT,
		"the refused code was not stored"
	);
	// Another client is not affected by the first one's codes.
	let (status, body) = authorize(&app, "198.51.100.2").await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_pool_of_codes_has_a_ceiling() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		// A full pool, spread over accounts and addresses so only the
		// ceiling of the pool is reached.
		let mut codes = authz.codes.lock().unwrap();
		for n in 0..super::pkce::MAX_AUTH_CODES {
			let ip = format!("198.51.{}.{}", n / 256, n % 256);
			codes.insert(
				format!("fill{n}"),
				code(&format!("acct{n}"), bucket(&ip), now() + 600),
			);
		}
	}
	let app = router(state.clone());
	let (status, body) = authorize(&app, "198.51.100.1").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"], "temporarily_unavailable");
	assert_eq!(
		authz.codes.lock().unwrap().len(),
		super::pkce::MAX_AUTH_CODES,
		"the refused code was not stored"
	);
}

#[tokio::test]
async fn expired_codes_are_swept_and_free_their_room() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		// Codes nobody redeemed: they are expired, so they hold no room.
		let mut codes = authz.codes.lock().unwrap();
		for n in 0..10 {
			codes.insert(
				format!("stale{n}"),
				code(ACCOUNT, bucket("198.51.100.1"), now() - 1),
			);
		}
	}
	let app = router(state.clone());
	let (status, body) = authorize(&app, "198.51.100.1").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let codes = authz.codes.lock().unwrap();
	assert_eq!(codes.len(), 1, "the expired codes are gone");
	assert!(codes.values().all(|c| c.expires_at > now()));
}

#[tokio::test]
async fn a_swept_pool_lets_the_capped_client_ask_again() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		let mut codes = authz.codes.lock().unwrap();
		for n in 0..super::pkce::MAX_CODES_PER_ACCOUNT {
			codes.insert(
				format!("old{n}"),
				code(ACCOUNT, bucket("198.51.100.1"), now() + 600),
			);
		}
	}
	let app = router(state.clone());
	let (status, body) = authorize(&app, "198.51.100.1").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	// The codes of that account expire; the next request sweeps them and is
	// answered.
	{
		let mut codes = authz.codes.lock().unwrap();
		for c in codes.values_mut() {
			c.expires_at = now() - 1;
		}
	}
	let (status, body) = authorize(&app, "198.51.100.1").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(authz.codes.lock().unwrap().len(), 1);
}
