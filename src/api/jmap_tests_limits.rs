//! The limits the JMAP Session advertises are the limits the server applies
//! (RFC 8620 §2, §3.6.1): `maxCallsInRequest` and `maxSizeRequest`.

use super::Principal;
use super::jmap::websocket::{PushState, handle_ws_message};
use super::jmap::{MAX_CALLS_IN_REQUEST, MAX_SIZE_REQUEST};
use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

const CORE: &str = "urn:ietf:params:jmap:core";

fn echo_calls(count: usize) -> Value {
	let calls: Vec<Value> = (0..count)
		.map(|i| json!(["Core/echo", { "n": i }, format!("c{i}")]))
		.collect();
	json!({ "using": [CORE], "methodCalls": calls })
}

/// A valid `Core/echo` request whose serialised body is exactly `size` octets.
fn request_of_size(size: usize) -> Vec<u8> {
	let shell = json!({
		"using": [CORE],
		"methodCalls": [["Core/echo", { "pad": "" }, "c1"]],
	})
	.to_string()
	.len();
	let body = json!({
		"using": [CORE],
		"methodCalls": [["Core/echo", { "pad": "a".repeat(size - shell) }, "c1"]],
	})
	.to_string()
	.into_bytes();
	assert_eq!(body.len(), size, "the helper builds the exact size");
	body
}

async fn post_bytes(app: &Router, body: Vec<u8>) -> (StatusCode, Value) {
	post_to(app, "/jmap/api", body).await
}

async fn post_to(app: &Router, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
	let request = Request::builder()
		.method("POST")
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.header(header::CONTENT_TYPE, "application/json")
		.body(Body::from(body))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	// A transport-level rejection may carry a plain-text body.
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(Value::Null),
	)
}

#[tokio::test]
async fn session_advertises_the_enforced_limits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, body) = request(&app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	let core = &body["capabilities"][CORE];
	assert_eq!(core["maxCallsInRequest"], MAX_CALLS_IN_REQUEST);
	assert_eq!(core["maxSizeRequest"], MAX_SIZE_REQUEST);
}

#[tokio::test]
async fn sixteen_calls_are_answered_and_seventeen_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(echo_calls(MAX_CALLS_IN_REQUEST)),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"].as_array().map(Vec::len),
		Some(MAX_CALLS_IN_REQUEST)
	);

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(echo_calls(MAX_CALLS_IN_REQUEST + 1)),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit");
	assert_eq!(body["limit"], "maxCallsInRequest");
	assert_eq!(body["status"], 400);
	assert!(
		body.get("methodResponses").is_none(),
		"no call is run when the request is refused: {body}"
	);
}

#[tokio::test]
async fn a_body_at_the_advertised_size_is_accepted_and_one_more_octet_is_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = post_bytes(&app, request_of_size(MAX_SIZE_REQUEST)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][0], "Core/echo");

	let (status, body) = post_bytes(&app, request_of_size(MAX_SIZE_REQUEST + 1)).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit", "{body}");
	assert_eq!(body["limit"], "maxSizeRequest", "{body}");
	assert_eq!(body["status"], 413, "{body}");
}

/// The upload body cap is `maxSizeUpload` itself: any larger body, however
/// much larger, is answered with the same `limit` problem, never with a bare
/// transport rejection a client cannot tell apart from a broken proxy.
#[tokio::test]
async fn an_upload_far_over_max_size_upload_gets_the_limit_problem() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// The configured `[server] max_message_size` drives the upload route's
	// body limit. One MiB over is enough to trip it without building a
	// 50 MiB+ buffer in a unit test.
	let body = vec![0u8; crate::smtp::session::MAX_MESSAGE_SIZE + 1024 * 1024];

	let (status, body) = post_to(&app, "/jmap/upload/alice", body).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit", "{body}");
	assert_eq!(body["limit"], "maxSizeUpload", "{body}");
}

/// A WebSocket `Request` frame is a request like any other: over
/// `maxSizeRequest` it is refused with the `limit` problem, as a
/// `RequestError` echoing the frame's id, and nothing in it runs.
#[test]
fn a_websocket_request_over_max_size_request_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let principal = Principal::Admin { credential: None };
	let mut push = PushState::default();
	let frame = |size: usize| {
		let shell = json!({
			"@type": "Request", "id": "big",
			"methodCalls": [["Core/echo", { "pad": "" }, "c1"]],
		})
		.to_string()
		.len();
		json!({
			"@type": "Request", "id": "big",
			"methodCalls": [["Core/echo", { "pad": "a".repeat(size - shell) }, "c1"]],
		})
		.to_string()
	};

	let replies = handle_ws_message(&state, &principal, &frame(MAX_SIZE_REQUEST), &mut push);
	let reply: Value = serde_json::from_str(&replies[0]).expect("json");
	assert_eq!(reply["@type"], "Response");
	assert_eq!(reply["methodResponses"][0][0], "Core/echo");

	let replies = handle_ws_message(&state, &principal, &frame(MAX_SIZE_REQUEST + 1), &mut push);
	assert_eq!(replies.len(), 1);
	let reply: Value = serde_json::from_str(&replies[0]).expect("json");
	// The reply is not printed on failure: a wrongly accepted frame echoes
	// ten megabytes back.
	assert_eq!(reply["@type"], "RequestError");
	assert_eq!(reply["type"], "urn:ietf:params:jmap:error:limit");
	assert_eq!(reply["limit"], "maxSizeRequest");
	assert_eq!(reply["requestId"], "big");
	assert!(reply.get("methodResponses").is_none());
}
