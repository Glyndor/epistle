//! Host isolation, untrusted forwarding, bounded heads and HTTP/1 framing.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use serde_json::Value;

use super::harness::{ADMIN, ALICE, Harness, Wire, api_request, call};

#[tokio::test]
async fn strange_host_cannot_change_session_authority_or_account() {
	let h = Harness::new();
	for host in [
		"attacker.invalid:65535",
		"alice@attacker.invalid",
		"[::1]:9999",
		"example.test.attacker.invalid",
		"example.test,attacker.invalid",
	] {
		let mut request = api_request("GET", "/jmap/session", ALICE, Body::empty());
		request
			.headers_mut()
			.insert("host", host.parse().expect("host value"));
		let reply = call(&h.api, request).await;
		assert_eq!(reply.status, StatusCode::OK);
		let body = reply.json();
		assert_eq!(body["apiUrl"], "/jmap/api");
		assert_eq!(body["uploadUrl"], "/jmap/upload/{accountId}");
		let accounts = body["accounts"].as_object().expect("accounts");
		assert_eq!(accounts.len(), 1);
		assert!(accounts.contains_key("alice"));
		assert!(!String::from_utf8_lossy(&reply.body).contains("attacker.invalid"));
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn nul_in_host_is_rejected_by_http_parser() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"GET /api/v1/accounts HTTP/1.1\r\nHost: bad\0host\r\nAuthorization: Bearer {ADMIN}\r\nConnection: close\r\n\r\n"
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
async fn giant_header_is_refused_before_authentication() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"GET /api/v1/accounts HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ADMIN}\r\nX-Padding: {}\r\nConnection: close\r\n\r\n",
		"x".repeat(128 * 1024)
	);
	let reply = wire.exchange(request.as_bytes(), false).await;
	assert!(
		reply.is_empty() || reply.starts_with(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"),
		"{}",
		String::from_utf8_lossy(&reply)
	);
	wire.healthy().await;
	h.healthy_api().await;
}

#[tokio::test]
async fn rotating_untrusted_xff_cannot_evade_or_move_failure_budget() {
	let h = Harness::new();
	let attacker = "198.51.100.41:4444"
		.parse::<std::net::SocketAddr>()
		.expect("peer");
	for n in 0..22 {
		let mut request = api_request("GET", "/api/v1/accounts", "wrong", Body::empty());
		request.extensions_mut().insert(ConnectInfo(attacker));
		let xff = if n == 0 {
			"192.0.2.10".to_string()
		} else {
			format!("203.0.113.{n}")
		};
		request
			.headers_mut()
			.insert("x-forwarded-for", xff.parse().expect("XFF"));
		let reply = call(&h.api, request).await;
		assert_eq!(
			reply.status,
			if n < 20 {
				StatusCode::UNAUTHORIZED
			} else {
				StatusCode::TOO_MANY_REQUESTS
			},
			"request {}",
			n + 1
		);
		// The spoofed victim and the administrator's real peer remain usable.
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn malformed_xff_cannot_free_an_exhausted_peer() {
	let h = Harness::new();
	let peer = "198.51.100.42:4444"
		.parse::<std::net::SocketAddr>()
		.expect("peer");
	for _ in 0..20 {
		let mut request = api_request("GET", "/api/v1/accounts", "wrong", Body::empty());
		request.extensions_mut().insert(ConnectInfo(peer));
		assert_eq!(call(&h.api, request).await.status, StatusCode::UNAUTHORIZED);
	}
	for xff in [
		"garbage",
		"192.0.2.10,",
		"192.0.2.10:1234",
		"unknown, 192.0.2.10",
	] {
		let mut request = api_request("GET", "/api/v1/accounts", ADMIN, Body::empty());
		request.extensions_mut().insert(ConnectInfo(peer));
		request
			.headers_mut()
			.insert("x-forwarded-for", xff.parse().expect("XFF"));
		assert_eq!(
			call(&h.api, request).await.status,
			StatusCode::TOO_MANY_REQUESTS
		);
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn cl_te_with_invalid_chunk_framing_is_rejected() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{{}}\r\n"
	);
	let reply = wire.exchange(request.as_bytes(), true).await;
	assert!(
		reply.is_empty() || reply.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
		"{}",
		String::from_utf8_lossy(&reply)
	);
	assert!(!h.root().join("blobs/accounts/alice").exists());
	wire.healthy().await;
	h.healthy_api().await;
}

#[tokio::test]
async fn cl_te_cannot_promote_chunk_payload_to_a_second_request() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let payload = format!(
		"DELETE /api/v1/accounts/bob HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ADMIN}\r\n\r\n"
	);
	// The two framing schemes disagree. Chunked framing must remain authoritative.
	let deceptive_length = format!("{:x}\r\n", payload.len()).len();
	let request = format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: text/plain\r\nContent-Length: {deceptive_length}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{payload}\r\n0\r\n\r\n",
		payload.len()
	);
	let reply = wire.exchange(request.as_bytes(), false).await;
	// A strict parser may reject the ambiguous head entirely.
	if reply.is_empty() || reply.starts_with(b"HTTP/1.1 400 Bad Request\r\n") {
		assert!(!h.root().join("blobs/accounts/alice").exists());
	} else {
		assert!(
			reply.starts_with(b"HTTP/1.1 200 OK\r\n"),
			"{}",
			String::from_utf8_lossy(&reply)
		);
		assert_eq!(reply.windows(9).filter(|w| *w == b"HTTP/1.1 ").count(), 1);
		let separator = reply
			.windows(4)
			.position(|w| w == b"\r\n\r\n")
			.expect("HTTP head");
		let uploaded: Value =
			serde_json::from_slice(&reply[separator + 4..]).expect("fixed-length upload response");
		assert_eq!(uploaded["size"], payload.len());
		let id = uploaded["blobId"].as_str().expect("blob id");
		let download = call(
			&h.api,
			api_request(
				"GET",
				&format!("/jmap/download/alice/{id}/f"),
				ALICE,
				Body::empty(),
			),
		)
		.await;
		assert_eq!(download.status, StatusCode::OK);
		assert_eq!(download.body, payload.as_bytes());
	}
	// Account count and the presence of bob detect execution even if its reply is suppressed.
	wire.healthy().await;
	h.healthy_api().await;
}
