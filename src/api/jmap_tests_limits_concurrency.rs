//! `maxConcurrentRequests` and `maxConcurrentUpload` (RFC 8620 §2) are what
//! the server applies, per credential: past them a request is refused with
//! the `limit` problem naming the limit (§3.6.1), and another credential is
//! not held back by it.
//!
//! A request stays in flight here by never finishing its body, so the test
//! holds the slots the way a slow client would.

use super::jmap::websocket::{PushState, handle_ws_message};
use super::jmap::{MAX_CONCURRENT_REQUESTS, MAX_CONCURRENT_UPLOAD};
use super::jmap_tests_principal_b::{key, state_with_key};
use super::router;
use super::tests::TOKEN;
use crate::api::{Credential, Principal};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::task::JoinHandle;
use tower::ServiceExt;

const CORE: &str = "urn:ietf:params:jmap:core";
const SECRET: &str = "concurrency-secret";

/// A body that never yields a chunk nor ends.
struct Stalled;

impl futures_core::Stream for Stalled {
	type Item = Result<Bytes, std::io::Error>;

	fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		Poll::Pending
	}
}

fn app(dir: &std::path::Path) -> Router {
	let state = state_with_key(dir, key(SECRET, &[], None, None));
	// The requests are held in flight with a short settle: the configured
	// token must already be known, or its first argon2 outlasts the settle.
	state.prime_configured_token(TOKEN.as_str());
	router(state)
}

/// Start `count` requests to `path` whose bodies never arrive, and let each
/// run as far as it can.
async fn hold(app: &Router, path: &str, count: usize) -> Vec<JoinHandle<()>> {
	let held = (0..count)
		.map(|_| {
			let request = Request::builder()
				.method("POST")
				.uri(path)
				.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
				.header(header::CONTENT_TYPE, "application/json")
				.body(Body::from_stream(Stalled))
				.expect("request");
			let app = app.clone();
			tokio::spawn(async move {
				app.oneshot(request).await.ok();
			})
		})
		.collect();
	settle().await;
	held
}

/// Let every spawned request run until it waits on its body.
async fn settle() {
	for _ in 0..50 {
		tokio::task::yield_now().await;
	}
}

/// Stop the held requests, as a client that hangs up does.
async fn release(held: Vec<JoinHandle<()>>) {
	for handle in held {
		handle.abort();
		handle.await.ok();
	}
}

async fn post(app: &Router, path: &str, token: &str, body: &[u8]) -> (StatusCode, Value) {
	let request = Request::builder()
		.method("POST")
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(Body::from(body.to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(Value::Null),
	)
}

fn echo() -> Vec<u8> {
	json!({ "using": [CORE], "methodCalls": [["Core/echo", {}, "c1"]] })
		.to_string()
		.into_bytes()
}

#[tokio::test]
async fn session_advertises_the_enforced_concurrency_limits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let request = Request::builder()
		.uri("/jmap/session")
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.body(Body::empty())
		.expect("request");
	let response = app.oneshot(request).await.expect("response");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let body: Value = serde_json::from_slice(&bytes).expect("json");
	let core = &body["capabilities"][CORE];
	assert_eq!(core["maxConcurrentRequests"], MAX_CONCURRENT_REQUESTS);
	assert_eq!(core["maxConcurrentUpload"], MAX_CONCURRENT_UPLOAD);
}

#[tokio::test]
async fn one_api_request_past_max_concurrent_requests_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let mut held = hold(&app, "/jmap/api", MAX_CONCURRENT_REQUESTS).await;

	let (status, body) = post(&app, "/jmap/api", TOKEN.as_str(), &echo()).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit", "{body}");
	assert_eq!(body["limit"], "maxConcurrentRequests", "{body}");

	// The limit is the credential's: another key is not held back.
	let (status, body) = post(&app, "/jmap/api", SECRET, &echo()).await;
	assert_eq!(status, StatusCode::OK, "{body}");

	// Once one of the held requests ends, its slot is free again.
	release(vec![held.remove(0)]).await;
	let (status, body) = post(&app, "/jmap/api", TOKEN.as_str(), &echo()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["methodResponses"][0][0], "Core/echo", "{body}");
	release(held).await;
}

#[tokio::test]
async fn one_upload_past_max_concurrent_upload_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let mut held = hold(&app, "/jmap/upload/ann", MAX_CONCURRENT_UPLOAD).await;

	let (status, body) = post(&app, "/jmap/upload/ann", TOKEN.as_str(), b"blob").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit", "{body}");
	assert_eq!(body["limit"], "maxConcurrentUpload", "{body}");

	// Uploads and API requests are counted apart.
	let (status, body) = post(&app, "/jmap/api", TOKEN.as_str(), &echo()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = post(&app, "/jmap/upload/ann", SECRET, b"blob").await;
	assert_eq!(status, StatusCode::OK, "{body}");

	release(vec![held.remove(0)]).await;
	let (status, body) = post(&app, "/jmap/upload/ann", TOKEN.as_str(), b"blob").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["size"], 4, "{body}");
	release(held).await;
}

/// A WebSocket `Request` is an API request of the same credential: it waits
/// for no slot either, and is refused with a `RequestError` naming the limit.
#[tokio::test]
async fn a_websocket_request_counts_against_max_concurrent_requests() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_key(dir.path(), key(SECRET, &[], None, None));
	state.prime_configured_token(TOKEN.as_str());
	let app = router(state.clone());
	let held = hold(&app, "/jmap/api", MAX_CONCURRENT_REQUESTS).await;

	let frame = json!({
		"@type": "Request", "id": "w1",
		"methodCalls": [["Core/echo", {}, "c1"]],
	})
	.to_string();
	let mut push = PushState::default();
	let token = Principal::unrestricted();
	let replies = handle_ws_message(&state, &token, &frame, &mut push);
	let reply: Value = serde_json::from_str(&replies[0]).expect("json");
	assert_eq!(reply["@type"], "RequestError", "{reply}");
	assert_eq!(reply["limit"], "maxConcurrentRequests", "{reply}");
	assert_eq!(reply["requestId"], "w1", "{reply}");

	let other = Principal::of_key(
		&key(SECRET, &[], None, None),
		Some(Credential {
			token: SECRET.to_string(),
			client_ip: None,
		}),
	);
	let replies = handle_ws_message(&state, &other, &frame, &mut push);
	let reply: Value = serde_json::from_str(&replies[0]).expect("json");
	assert_eq!(reply["@type"], "Response", "{reply}");
	release(held).await;
}
