use super::*;
use axum::body::Bytes;
use axum::http::{HeaderName, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, head, post};

/// Spawn an in-process ACME-like server and return its base URL.
async fn mock_server() -> String {
	async fn directory() -> &'static str {
		r#"{"newNonce":"/nonce"}"#
	}
	async fn nonce() -> impl IntoResponse {
		([(HeaderName::from_static("replay-nonce"), "nonce-1")], "")
	}
	async fn order() -> impl IntoResponse {
		(
			StatusCode::CREATED,
			[
				(HeaderName::from_static("replay-nonce"), "nonce-2"),
				(HeaderName::from_static("location"), "/order/1"),
			],
			r#"{"status":"pending"}"#,
		)
	}
	// Body sizes the test fixtures pin to a value in their own scope, so the
	// cap can shrink or grow without resizing the payloads the server
	// actually sends (which would OOM if we grew the payload with a
	// usize::MAX cap during the deletion-control experiment). `SMALL` sits
	// at 1 KiB and `OVER_CAP` at twice the production cap; both are well
	// within what an in-process test should allocate.
	const SMALL: usize = 1024;
	const OVER_CAP: usize = 1024 * 1024 * 2;

	// /small: well under the cap. The transport must pass it through.
	async fn small() -> Bytes {
		Bytes::from(vec![b'x'; SMALL])
	}
	// /over_cap: a body two times the production cap, so the fixture
	// always overshoots the configured cap by a healthy margin. The
	// transport must reject it as soon as the chunked accumulation
	// crosses the cap, regardless of what `content_length` would claim.
	async fn over_cap() -> Bytes {
		Bytes::from(vec![b'y'; OVER_CAP])
	}
	async fn over_cap_post() -> Bytes {
		over_cap().await
	}
	// /refused: a CA that answers a GET with a problem document instead
	// of the resource that was asked for.
	async fn refused() -> impl IntoResponse {
		(
			StatusCode::BAD_REQUEST,
			"{\n  \"type\": \"urn:ietf:params:acme:error:malformed\",\n  \
				 \"detail\": \"Request message was malformed\",\n  \"status\": 400\n}\n",
		)
	}
	// /refused_nonce: a HEAD answered with a status and no body.
	async fn refused_nonce() -> impl IntoResponse {
		(StatusCode::SERVICE_UNAVAILABLE, "")
	}
	let app = axum::Router::new()
		.route("/dir", get(directory))
		.route("/nonce", head(nonce))
		.route("/order", post(order))
		.route("/small", get(small))
		.route("/over_cap", get(over_cap))
		.route("/over_cap_post", post(over_cap_post))
		.route("/refused", get(refused))
		.route("/refused_nonce", head(refused_nonce));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});
	format!("http://{addr}")
}

#[tokio::test]
async fn get_nonce_and_post_round_trip() {
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");

	let body = transport.get(&format!("{base}/dir")).await.expect("get");
	assert!(body.starts_with(b"{\"newNonce\""));

	let nonce = transport
		.new_nonce(&format!("{base}/nonce"))
		.await
		.expect("nonce");
	assert_eq!(nonce, "nonce-1");

	let response = transport
		.post(&format!("{base}/order"), "signed-jws")
		.await
		.expect("post");
	assert_eq!(response.status, 201);
	assert_eq!(response.nonce, "nonce-2");
	assert_eq!(response.location.as_deref(), Some("/order/1"));
	assert!(response.body.starts_with(b"{\"status\""));
}

#[tokio::test]
async fn new_nonce_without_header_errors() {
	// /dir answers GET but not a HEAD with a nonce header.
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");
	assert!(transport.new_nonce(&format!("{base}/dir")).await.is_err());
}

#[tokio::test]
async fn unreachable_endpoint_is_transport_error() {
	let transport = HttpTransport::new().expect("transport");
	assert!(transport.get("http://127.0.0.1:1/dir").await.is_err());
	assert!(transport.new_nonce("http://127.0.0.1:1/n").await.is_err());
	assert!(transport.post("http://127.0.0.1:1/o", "j").await.is_err());
}

#[tokio::test]
async fn get_body_under_cap_passes_through() {
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");
	let body = transport
		.get(&format!("{base}/small"))
		.await
		.expect("small body should pass the cap");
	assert_eq!(body.len(), 1024);
}

#[tokio::test]
async fn get_body_over_cap_fails_naming_the_limit() {
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");
	let error = transport
		.get(&format!("{base}/over_cap"))
		.await
		.expect_err("cap should reject bodies past the limit");
	let message = match error {
		AcmeError::Transport(s) => s,
		other => panic!("expected AcmeError::Transport, got {other:?}"),
	};
	assert!(
		message.contains("body cap"),
		"error must name the cap: {message}"
	);
	assert!(
		message.contains(&MAX_ACME_BODY_BYTES.to_string()),
		"error must name the cap value ({}): {message}",
		MAX_ACME_BODY_BYTES
	);
}

#[tokio::test]
async fn post_body_over_cap_fails_naming_the_limit() {
	// Same cap applies to POST responses, where the cert chain comes back.
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");
	let error = transport
		.post(&format!("{base}/over_cap_post"), "signed-jws")
		.await
		.expect_err("post cap should reject bodies past the limit");
	let message = match error {
		AcmeError::Transport(s) => s,
		other => panic!("expected AcmeError::Transport, got {other:?}"),
	};
	assert!(
		message.contains(&MAX_ACME_BODY_BYTES.to_string()),
		"error must name the cap value ({}): {message}",
		MAX_ACME_BODY_BYTES
	);
}

#[tokio::test]
async fn a_refused_get_names_the_reason() {
	// The directory is fetched with GET. A refusal carries a problem
	// document, not a directory, and the reason it names is what the
	// operator has to read.
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");
	let error = transport
		.get(&format!("{base}/refused"))
		.await
		.expect_err("a refused GET must fail");
	let message = error.to_string();
	assert!(
		message.contains("urn:ietf:params:acme:error:malformed"),
		"the reason must be named: {message}"
	);
	assert!(
		message.contains("Request message was malformed"),
		"the detail must be named: {message}"
	);
}

#[tokio::test]
async fn a_refused_nonce_names_the_status() {
	// A HEAD answer carries no body, so the status is all there is.
	let base = mock_server().await;
	let transport = HttpTransport::new().expect("transport");
	let error = transport
		.new_nonce(&format!("{base}/refused_nonce"))
		.await
		.expect_err("a refused nonce must fail");
	let message = error.to_string();
	assert!(
		message.contains("503"),
		"the status must be named: {message}"
	);
}
