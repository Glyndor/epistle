//! The addresses of a suspended account: a key confined to domains changes
//! none. One taken off would be free to give to an account that is not
//! suspended.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

async fn remove(world: &World, bearer: &str) -> (StatusCode, serde_json::Value) {
	call(
		&world.state,
		"DELETE",
		"/api/v1/accounts/alice/addresses/alice2@a.test",
		bearer,
		None,
	)
	.await
}

#[tokio::test]
async fn a_confined_key_takes_no_address_off_a_suspended_account() {
	let world = world();
	world.store.set_disabled("alice", true).expect("suspend");
	let (status, body) = remove(&world, OF_A).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(body.to_string().contains("suspended"), "{body}");
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
	// Nor does it give it one more.
	let (status, body) = call(
		&world.state,
		"POST",
		"/api/v1/accounts/alice/addresses",
		OF_A,
		Some(json!({"address": "more@a.test"})),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(body.to_string().contains("suspended"), "{body}");
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
	// A suspended account of another tenant is as absent as any other.
	world.store.set_disabled("bob", true).expect("suspend");
	let (status, _) = call(
		&world.state,
		"DELETE",
		"/api/v1/accounts/bob/addresses/bob@b.test",
		OF_A,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unconfined_key_takes_an_address_off_a_suspended_account() {
	for bearer in [token(), WRITER] {
		let world = world();
		world.store.set_disabled("alice", true).expect("suspend");
		let (status, body) = remove(&world, bearer).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		assert_eq!(addresses(&world, "alice"), ["alice@a.test"]);
	}
}

#[tokio::test]
async fn an_unconfined_key_gives_an_address_to_a_suspended_account() {
	for bearer in [token(), WRITER] {
		let world = world();
		world.store.set_disabled("alice", true).expect("suspend");
		let (status, body) = call(
			&world.state,
			"POST",
			"/api/v1/accounts/alice/addresses",
			bearer,
			Some(json!({"address": "more@a.test"})),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{body}");
	}
}
