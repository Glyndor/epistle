//! Management authentication, parser limits, route boundaries and failure budgets.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, StatusCode};

use super::harness::{ADMIN, ALICE, Harness, Wire, api_request, call, repeated_body};

#[tokio::test]
async fn missing_or_malformed_authorization_never_authenticates() {
	let h = Harness::new();
	for value in [
		None,
		Some(""),
		Some("Bearer"),
		Some("Bearer "),
		Some("Basic Zm9vOmJhcg=="),
		Some("Bearers hostile-http-admin-fixture"),
		Some("bearer hostile-http-admin-fixture"),
	] {
		let mut request = api_request("GET", "/api/v1/accounts", ADMIN, Body::empty());
		request.headers_mut().remove("authorization");
		if let Some(value) = value {
			request
				.headers_mut()
				.insert("authorization", HeaderValue::from_static(value));
		}
		let reply = call(&h.api, request).await;
		assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{value:?}");
		assert!(reply.json().get("accounts").is_none());
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn matching_token_prefixes_and_suffixes_do_not_authenticate() {
	let h = Harness::new();
	for valid in [ADMIN, ALICE] {
		let candidates = [
			valid[..valid.len() - 1].to_string(),
			format!("{valid}x"),
			format!("x{}", &valid[1..]),
			format!("{valid},ignored"),
		];
		for token in candidates {
			let reply = call(
				&h.api,
				api_request("GET", "/api/v1/accounts", &token, Body::empty()),
			)
			.await;
			assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
			h.healthy_api().await;
		}
	}
}

#[tokio::test]
async fn bearer_over_parser_limit_is_rejected() {
	let h = Harness::new();
	let request = api_request("GET", "/api/v1/accounts", &"x".repeat(1025), Body::empty());
	assert_eq!(call(&h.api, request).await.status, StatusCode::UNAUTHORIZED);
	h.healthy_api().await;
}

#[tokio::test]
async fn unsupported_management_method_returns_405() {
	let h = Harness::new();
	let reply = call(
		&h.api,
		api_request("PATCH", "/api/v1/accounts", ADMIN, Body::from("{}")),
	)
	.await;
	assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
	let allow = reply
		.headers
		.get("allow")
		.expect("allowed methods")
		.to_str()
		.expect("ASCII allow");
	assert!(allow.split(',').any(|m| m.trim() == "GET"));
	assert!(!allow.split(',').any(|m| m.trim() == "PATCH"));
	h.healthy_api().await;
}

#[tokio::test]
async fn hundred_thousand_json_levels_are_refused_without_account_creation() {
	let h = Harness::new();
	// Keep the raw string flat in the test process; never construct a deep Value.
	let body = format!(
		"{{\"name\":{}0{}}}",
		"[".repeat(100_000),
		"]".repeat(100_000)
	);
	let reply = call(
		&h.api,
		api_request("POST", "/api/v1/accounts", ADMIN, Body::from(body)),
	)
	.await;
	assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
	h.healthy_api().await;
}

#[tokio::test]
async fn management_json_over_default_limit_is_refused() {
	let h = Harness::new();
	let request = api_request(
		"POST",
		"/api/v1/accounts",
		ADMIN,
		repeated_body(2 * 1024 * 1024 + 1),
	);
	assert_eq!(
		call(&h.api, request).await.status,
		StatusCode::PAYLOAD_TOO_LARGE
	);
	h.healthy_api().await;
}

#[tokio::test]
async fn send_json_over_configured_limit_is_refused() {
	let h = Harness::new();
	let request = api_request(
		"POST",
		"/api/v1/send",
		ADMIN,
		repeated_body(super::harness::UPLOAD_LIMIT + 1),
	);
	assert_eq!(
		call(&h.api, request).await.status,
		StatusCode::PAYLOAD_TOO_LARGE
	);
	h.healthy_api().await;
}

#[tokio::test]
async fn management_traversal_routes_do_not_resolve() {
	let h = Harness::new();
	for path in [
		"/api/v1/../accounts",
		"/api/v1/%2e%2e/accounts",
		"/api/v1/accounts/../../domains",
	] {
		let reply = call(&h.api, api_request("GET", path, ADMIN, Body::empty())).await;
		assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn account_key_cannot_enter_management_routes() {
	let h = Harness::new();
	for path in ["/api/v1/accounts", "/api/v1/domains", "/api/v1/queue"] {
		assert_eq!(
			call(&h.api, api_request("GET", path, ALICE, Body::empty()))
				.await
				.status,
			StatusCode::FORBIDDEN
		);
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn twenty_failures_limit_only_the_attacking_peer() {
	let h = Harness::new();
	for n in 0..22 {
		let mut request = api_request("GET", "/api/v1/accounts", "wrong", Body::empty());
		request.extensions_mut().insert(ConnectInfo(
			"198.51.100.99:1234"
				.parse::<std::net::SocketAddr>()
				.expect("attacker"),
		));
		let reply = call(&h.api, request).await;
		let expected = if n < 20 {
			StatusCode::UNAUTHORIZED
		} else {
			StatusCode::TOO_MANY_REQUESTS
		};
		assert_eq!(reply.status, expected, "failure {}", n + 1);
		if n >= 20 {
			let retry: u64 = reply.headers["retry-after"]
				.to_str()
				.expect("retry ASCII")
				.parse()
				.expect("retry seconds");
			assert!(retry > 0 && retry <= 60);
		}
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn conflicting_content_lengths_are_rejected_on_wire() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"POST /api/v1/accounts HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ADMIN}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{{}}"
	);
	let reply = wire.exchange(request.as_bytes(), false).await;
	assert!(
		reply.is_empty() || reply.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
		"{}",
		String::from_utf8_lossy(&reply)
	);
	wire.healthy().await;
	h.healthy_api().await;
}

#[tokio::test]
async fn truncated_content_length_cannot_create_an_account() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"POST /api/v1/accounts HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ADMIN}\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{{}}"
	);
	let reply = wire.exchange(request.as_bytes(), true).await;
	// EOF may close the connection before a response can be written.
	assert!(
		reply.is_empty() || reply.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
		"{}",
		String::from_utf8_lossy(&reply)
	);
	wire.healthy().await;
	h.healthy_api().await;
}
