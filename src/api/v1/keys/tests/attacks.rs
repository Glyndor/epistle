//! Hostile requests.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

#[tokio::test]
async fn a_body_that_is_not_the_shape_makes_nothing() {
	let world = world();
	for body in [
		json!({"scopes": ["read"]}),
		json!({"label": "x"}),
		json!({"label": "x", "scopes": "read"}),
		json!({"label": "x", "scopes": ["read"], "hash": "sha256:00"}),
		json!({"label": "x", "scopes": ["read"], "expires_at": "2099-01-01", "expires_in": "1d"}),
		json!({"label": "x", "scopes": ["read"], "expires_in": "forever"}),
		json!({"label": "x", "scopes": ["read"], "expires_at": "2001-01-01"}),
		json!({"label": "x", "scopes": ["read"], "expires_at": "1700000000"}),
		json!({"label": " x", "scopes": ["read"]}),
		json!({"label": "a\u{0}b", "scopes": ["read"]}),
		json!({"label": "x".repeat(200), "scopes": ["read"]}),
		json!({"label": "x", "scopes": ["READ"]}),
		json!({"label": "x", "scopes": ["read"], "ip_cidr": "nowhere"}),
		json!({"label": "x", "scopes": ["read"], "account": "nobody"}),
		json!({"label": "x", "scopes": ["read"], "domains": ["not-hosted.example"]}),
	] {
		let (status, _, reply) = call(
			&world.state,
			"POST",
			"/api/v1/keys",
			token(),
			Some(body.clone()),
		)
		.await;
		assert!(status.is_client_error(), "{body}: {status} {reply}");
	}
	assert_eq!(labels(&world).len(), 7, "{:?}", labels(&world));
}

#[tokio::test]
async fn a_body_past_the_limit_is_refused() {
	let world = world();
	let (status, _, _) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		token(),
		Some(json!({"label": "x", "scopes": ["read"], "pad": "y".repeat(9000)})),
	)
	.await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert_eq!(labels(&world).len(), 7);
}

#[tokio::test]
async fn a_revoke_of_a_name_that_is_not_a_label_is_not_found() {
	let world = world();
	for label in [
		"",
		"%00",
		"..%2F..%2Fetc%2Fpasswd",
		"of-a%20",
		"OF-A",
		"of-a%0A",
	] {
		let (status, _, _) = call(
			&world.state,
			"DELETE",
			&format!("/api/v1/keys/{label}"),
			token(),
			None,
		)
		.await;
		assert!(status.is_client_error(), "{label}: {status}");
	}
	assert_eq!(labels(&world).len(), 7);
}

#[tokio::test]
async fn the_domains_a_key_names_are_hosted_and_few() {
	let world = world();
	let (status, _, body) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		MAKER,
		Some(json!({"label": "x", "scopes": ["read"], "domains": ["elsewhere.example"]})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let many: Vec<String> = (0..40).map(|n| format!("d{n}.example")).collect();
	let (status, _, body) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		token(),
		Some(json!({"label": "x", "scopes": ["read"], "domains": many})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
