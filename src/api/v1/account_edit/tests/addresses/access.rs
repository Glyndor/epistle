//! Who may change the addresses of an account: a key that manages, inside its
//! own domains, and never a key bound to an account.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

async fn add(
	world: &World,
	bearer: &str,
	name: &str,
	address: &str,
) -> (StatusCode, serde_json::Value) {
	let (status, body) = call(
		&world.state,
		"POST",
		&format!("/api/v1/accounts/{name}/addresses"),
		bearer,
		Some(json!({"address": address})),
	)
	.await;
	(status, body)
}

async fn remove(
	world: &World,
	bearer: &str,
	name: &str,
	address: &str,
) -> (StatusCode, serde_json::Value) {
	let (status, body) = call(
		&world.state,
		"DELETE",
		&format!("/api/v1/accounts/{name}/addresses/{address}"),
		bearer,
		None,
	)
	.await;
	(status, body)
}

#[tokio::test]
async fn a_key_that_does_not_write_changes_nothing() {
	let world = world();
	let (status, body) = add(&world, READER, "alice", "new@a.test").await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let (status, body) = remove(&world, READER, "alice", "alice2@a.test").await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let (status, _) = call(
		&world.state,
		"POST",
		"/api/v1/accounts/alice/addresses",
		"nope",
		Some(json!({"address": "x@a.test"})),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
}

#[tokio::test]
async fn a_key_bound_to_an_account_changes_no_addresses_not_even_its_own() {
	let world = world();
	let (status, body) = add(&world, OF_ALICE, "alice", "new@a.test").await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let (status, body) = remove(&world, OF_ALICE, "alice", "alice2@a.test").await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let (status, _) = add(&world, OF_ALICE, "bob", "new@b.test").await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
}

/// The tests the route rules name: a confined key reaches its own
/// accounts and domains and nothing else.
#[tokio::test]
async fn a_confined_key_adds_addresses_in_its_own_domains_only() {
	let world = world();
	let (status, body) = add(&world, OF_A, "alice", "new@a.test").await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	// An address in another tenant's domain, one in a domain that is hosted
	// and one that is not: the same refusal, so nothing tells which exist.
	let mut answers = Vec::new();
	for address in ["x@b.test", "x@c.test", "x@nowhere.example"] {
		let (status, body) = add(&world, OF_A, "alice", address).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{address}: {body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	// The case of the domain does not get an address past the check.
	let (status, _) = add(&world, OF_A, "alice", "Case@A.TEST").await;
	assert_eq!(status, StatusCode::CREATED);
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test", "case@a.test", "new@a.test"]
	);
}

#[tokio::test]
async fn an_account_of_another_tenant_is_the_same_404_as_one_that_is_not_there() {
	let world = world();
	let mut answers = Vec::new();
	for name in ["bob", "split", "nobody"] {
		let (status, body) = add(&world, OF_A, name, "x@a.test").await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{name}: {body}");
		answers.push(body);
		let (status, body) = remove(&world, OF_A, name, "bob@b.test").await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{name}: {body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert_eq!(addresses(&world, "bob"), ["bob@b.test"]);
	assert_eq!(addresses(&world, "split"), ["split@a.test", "split@b.test"]);
}

#[tokio::test]
async fn a_confined_key_removes_addresses_of_its_own_accounts_only() {
	let world = world();
	let (status, body) = remove(&world, OF_A, "alice", "alice2@a.test").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(addresses(&world, "alice"), ["alice@a.test"]);
	let (status, _) = remove(&world, OF_B, "alice", "alice@a.test").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(addresses(&world, "alice"), ["alice@a.test"]);
}

#[tokio::test]
async fn the_configured_token_and_an_unconfined_writer_reach_every_account() {
	let world = world();
	for (bearer, address) in [(token(), "t@c.test"), (WRITER, "w@c.test")] {
		let (status, body) = add(&world, bearer, "bob", address).await;
		assert_eq!(status, StatusCode::CREATED, "{body}");
	}
	let (status, body) = add(&world, WRITER, "bob", "x@nowhere.example").await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let (status, _) = add(&world, WRITER, "nobody", "x@c.test").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}
