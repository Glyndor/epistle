//! Hostile requests.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

async fn post(
	world: &World,
	bearer: &str,
	body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
	let (status, reply) = call(
		&world.state,
		"POST",
		"/api/v1/accounts/alice/addresses",
		bearer,
		Some(body),
	)
	.await;
	(status, reply)
}

#[tokio::test]
async fn a_body_that_is_not_the_shape_changes_nothing() {
	let world = world();
	for body in [
		json!({}),
		json!({"address": 7}),
		json!({"address": null}),
		json!({"address": ""}),
		json!({"address": "x@a.test", "account": "bob"}),
		json!({"address": "x@a.test", "dry_run": true}),
		json!("x@a.test"),
	] {
		let (status, reply) = post(&world, token(), body.clone()).await;
		assert!(
			status.is_client_error() && status != StatusCode::FORBIDDEN,
			"{body}: {status} {reply}"
		);
	}
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
}

#[tokio::test]
async fn an_address_that_is_not_one_is_refused_to_every_key() {
	let world = world();
	for address in [
		"no-at-sign",
		"x@",
		"@a.test",
		"x y@a.test",
		"x@a.test\r\nBcc: a@b.test",
		"x\u{0}@a.test",
		"x@a.test@a.test",
		"x@b.test@a.test",
		"\"x@b.test\"@a.test",
		"x@\u{202e}a.test",
		"x@a.test.",
		"x@[127.0.0.1]",
		&"x".repeat(400),
	] {
		for bearer in [token(), OF_A] {
			let (status, reply) = post(&world, bearer, json!({"address": address})).await;
			assert!(status.is_client_error(), "{address:?}: {status} {reply}");
		}
	}
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
	assert_eq!(addresses(&world, "bob"), ["bob@b.test"]);
}

/// An address is 320 characters at most: one more is refused for its length
/// before anything is looked up, and 320 reaches the store, which says what
/// else is wrong with it.
#[tokio::test]
async fn an_address_past_the_length_limit_is_refused_for_its_length() {
	let world = world();
	let of_length = |length: usize| format!("{}@a.test", "x".repeat(length - "@a.test".len()));
	for (length, out_of_range) in [(320, false), (321, true)] {
		let address = of_length(length);
		assert_eq!(address.len(), length);
		let (status, reply) = post(&world, token(), json!({"address": address})).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{length}: {reply}");
		assert_eq!(
			reply.to_string().contains("1 to 320 characters"),
			out_of_range,
			"add {length}: {reply}"
		);
		let (status, reply) = call(
			&world.state,
			"DELETE",
			&format!("/api/v1/accounts/alice/addresses/{address}"),
			token(),
			None,
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{length}: {reply}");
		assert_eq!(
			reply.to_string().contains("1 to 320 characters"),
			out_of_range,
			"remove {length}: {reply}"
		);
	}
	let (status, reply) = post(&world, token(), json!({"address": ""})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert!(reply.to_string().contains("1 to 320 characters"), "{reply}");
	assert_eq!(addresses(&world, "alice").len(), 2);
}

/// A body of 4096 bytes is read; one byte more is not.
#[tokio::test]
async fn the_body_limit_is_four_kibibytes() {
	let world = world();
	for (length, status) in [
		(4096, StatusCode::CREATED),
		(4097, StatusCode::PAYLOAD_TOO_LARGE),
	] {
		let mut body = format!(r#"{{"address":"n{length}@a.test"}}"#);
		body.push_str(&" ".repeat(length - body.len()));
		let request = axum::http::Request::builder()
			.method("POST")
			.uri("/api/v1/accounts/alice/addresses")
			.header("authorization", format!("Bearer {}", token()))
			.header("content-type", "application/json")
			.body(axum::body::Body::from(body))
			.unwrap();
		let response = tower::ServiceExt::oneshot(crate::api::router(world.state.clone()), request)
			.await
			.unwrap();
		assert_eq!(response.status(), status, "{length}");
	}
	assert_eq!(addresses(&world, "alice").len(), 3);
}

#[tokio::test]
async fn a_body_that_is_not_json_is_refused() {
	let world = world();
	let request = axum::http::Request::builder()
		.method("POST")
		.uri("/api/v1/accounts/alice/addresses")
		.header("authorization", format!("Bearer {}", token()))
		.header("content-type", "application/json")
		.body(axum::body::Body::from("{\"address\": "))
		.unwrap();
	let response = tower::ServiceExt::oneshot(crate::api::router(world.state.clone()), request)
		.await
		.unwrap();
	assert!(response.status().is_client_error());
	assert_eq!(addresses(&world, "alice").len(), 2);
}

#[tokio::test]
async fn a_removal_names_an_address_and_nothing_else() {
	let world = world();
	for address in [
		"",
		"%00",
		"..%2F..%2Fetc%2Fpasswd",
		"alice@a.test%0D%0ABcc:x@a.test",
		"%2A",
		"alice%40a.test%20x",
	] {
		let (status, _) = call(
			&world.state,
			"DELETE",
			&format!("/api/v1/accounts/alice/addresses/{address}"),
			token(),
			None,
		)
		.await;
		assert!(status.is_client_error(), "{address}: {status}");
	}
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
}
