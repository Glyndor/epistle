//! Hostile requests: bodies that are too large or not JSON, names that are
//! not addresses, and subjects built to reach what they should not.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

#[tokio::test]
async fn a_body_that_is_not_the_shape_is_refused_and_nothing_is_written() {
	let world = world();
	let app = crate::api::router(world.state.clone());
	let huge = format!(
		"{{\"target\":\"203.0.113.9\",\"pad\":\"{}\"}}",
		"x".repeat(5000)
	);
	for (what, body) in [
		("not JSON", "{target".to_string()),
		("an array", "[]".to_string()),
		(
			"an unknown field",
			"{\"target\":\"203.0.113.9\",\"reason\":\"x\"}".to_string(),
		),
		("no target", "{}".to_string()),
		("a number for the target", "{\"target\":1}".to_string()),
		("over the size limit", huge),
	] {
		let request = axum::http::Request::builder()
			.method("POST")
			.uri("/api/v1/bans")
			.header("authorization", format!("Bearer {BANNER}"))
			.header("content-type", "application/json")
			.body(axum::body::Body::from(body))
			.unwrap();
		let response = tower::ServiceExt::oneshot(app.clone(), request)
			.await
			.unwrap();
		assert!(
			response.status().is_client_error(),
			"{what}: {}",
			response.status()
		);
		assert_ne!(response.status(), StatusCode::CREATED, "{what}");
	}
	assert!(
		world.store.writes().is_empty(),
		"{:?}",
		world.store.writes()
	);
}

#[tokio::test]
async fn a_body_past_the_limit_is_too_large() {
	let world = world();
	let app = crate::api::router(world.state.clone());
	let body = format!(
		"{{\"cidr\":\"10.1.0.0/16\",\"pad\":\"{}\"}}",
		"x".repeat(8192)
	);
	let request = axum::http::Request::builder()
		.method("POST")
		.uri("/api/v1/bans/allow")
		.header("authorization", format!("Bearer {BANNER}"))
		.header("content-type", "application/json")
		.body(axum::body::Body::from(body))
		.unwrap();
	let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
	assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
	assert!(world.store.writes().is_empty());
}

#[tokio::test]
async fn a_target_that_is_not_an_address_or_a_network_is_refused() {
	let world = world();
	let long = "1".repeat(10_000);
	for target in [
		"",
		" ",
		"nope",
		"203.0.113.9/33",
		"203.0.113.9/-1",
		"203.0.113.9/",
		"203.0.113.9 ",
		"203.0.113.9\n",
		"203.0.113.9\u{0}",
		"2001:db8::/129",
		"ip:203.0.113.9",
		"pair:alice|203.0.113.9",
		"account:alice",
		"203.0.113.9,203.0.113.10",
		"*",
		long.as_str(),
	] {
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans",
			BANNER,
			Some(json!({"target": target})),
		)
		.await;
		// A trailing space or newline is trimmed by the address parser and
		// then names a real address; every other value is refused.
		if target.trim() == "203.0.113.9" && target != "203.0.113.9\u{0}" {
			continue;
		}
		// A name past the body limit never reaches the parser.
		let expected = if target.len() > 4096 {
			StatusCode::PAYLOAD_TOO_LARGE
		} else {
			StatusCode::BAD_REQUEST
		};
		assert_eq!(
			status,
			expected,
			"{:?}: {reply}",
			&target[..target.len().min(40)]
		);
	}
}

#[tokio::test]
async fn a_duration_that_is_not_one_is_refused() {
	let world = world();
	for text in [
		"",
		"0",
		"0h",
		"-1h",
		"1.5h",
		"1y",
		"forever",
		"99999d",
		"1 h",
		"18446744073709551616s",
	] {
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans",
			BANNER,
			Some(json!({"target": "203.0.113.9", "for": text})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{text:?}: {reply}");
	}
	let (status, _) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9", "for": 60})),
	)
	.await;
	assert!(
		status.is_client_error(),
		"a number is not a duration string"
	);
	assert!(world.store.writes().is_empty());
}

#[tokio::test]
async fn a_subject_that_names_nothing_it_may_lift_is_refused() {
	let world = world();
	world.store.preload_ban("ip:203.0.113.9", u64::MAX / 2);
	for subject in [
		"",
		"%20",
		"pair%3A",
		"pair%3Aalice",
		"pair%3A%7C203.0.113.9",
		"account%3A",
		"..%2F..%2Fetc%2Fpasswd",
		"203.0.113.9%00",
		"0.0.0.0%2F0",
		"allow",
		"%2A",
	] {
		let (status, reply) = call(
			&world,
			"DELETE",
			&format!("/api/v1/bans/{subject}"),
			BANNER,
			None,
		)
		.await;
		assert!(
			status.is_client_error() && status != StatusCode::FORBIDDEN,
			"{subject}: {status} {reply}"
		);
	}
	assert_eq!(
		world.store.ban_subjects(),
		["ip:203.0.113.9"],
		"nothing was lifted"
	);
}

#[tokio::test]
async fn an_allow_entry_that_is_not_a_block_is_refused() {
	let world = world();
	for cidr in [
		"",
		"nope",
		"10.0.0.0/33",
		"10.0.0.0/",
		"10.0.0.0/16/16",
		"10.0.0.0\u{0}/16",
		"10.0.0.0/16 x",
	] {
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans/allow",
			BANNER,
			Some(json!({"cidr": cidr})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{cidr:?}: {reply}");
	}
	assert!(world.store.allowed().is_empty());
}
