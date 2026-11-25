//! What a key may make, list and revoke: never more than it has.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

async fn make(
	bearer: &str,
	body: serde_json::Value,
	world: &World,
) -> (StatusCode, serde_json::Value) {
	let (status, _, reply) = call(&world.state, "POST", "/api/v1/keys", bearer, Some(body)).await;
	(status, reply)
}

/// Each of these asks for something the key that asks does not have.
#[tokio::test]
async fn a_key_cannot_make_a_key_with_more_than_it_has() {
	let world = world();
	for (what, body) in [
		(
			"a scope it lacks",
			json!({"label": "c", "scopes": ["write"], "domains": ["a.example"]}),
		),
		("every domain", json!({"label": "c", "scopes": ["read"]})),
		(
			"another domain",
			json!({"label": "c", "scopes": ["read"], "domains": ["b.example"]}),
		),
		(
			"both its domain and another",
			json!({"label": "c", "scopes": ["read"], "domains": ["a.example", "b.example"]}),
		),
		(
			"an account of another tenant",
			json!({"label": "c", "scopes": ["read"], "account": "bob"}),
		),
		(
			"the scope that opens the bans",
			json!({"label": "c", "scopes": ["ban"]}),
		),
	] {
		let (status, reply) = make(MAKER_A, body, &world).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {reply}");
		assert!(
			reply.to_string().contains("reaches further than itself"),
			"{what}: {reply}"
		);
		assert!(
			!labels(&world).contains(&"c".to_string()),
			"{what}: the key was made"
		);
	}
	// What it may, it makes.
	let (status, reply) = make(
		MAKER_A,
		json!({"label": "ok", "scopes": ["read", "key"], "domains": ["a.example"]}),
		&world,
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
	let (status, reply) = make(
		MAKER_A,
		json!({"label": "ann", "scopes": ["read"], "account": "ann"}),
		&world,
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
}

#[tokio::test]
async fn an_unconfined_key_makes_what_it_holds_and_no_more() {
	let world = world();
	let (status, _) = make(
		MAKER,
		json!({"label": "w", "scopes": ["read", "write"]}),
		&world,
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	for scope in ["send", "scim", "alias", "ban", "health"] {
		let (status, reply) = make(MAKER, json!({"label": "x", "scopes": [scope]}), &world).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{scope}: {reply}");
	}
	// The configured token holds every scope.
	let (status, _, _) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		token(),
		Some(json!({"label": "admin", "scopes": ["read", "write", "send", "scim", "alias", "ban", "health", "key"]})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
}

/// A key that expires, or is pinned to a network, makes keys that do too.
#[tokio::test]
async fn the_expiry_and_the_network_of_the_maker_bound_its_keys() {
	let world = world();
	let (status, _, body) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		token(),
		Some(json!({"label": "limited", "scopes": ["key", "read"], "expires_in": "7d", "ip_cidr": "127.0.0.0/8"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let limited = body["key"].as_str().unwrap().to_string();
	for (what, body) in [
		(
			"never expires",
			json!({"label": "n", "scopes": ["read"], "ip_cidr": "127.0.0.0/16"}),
		),
		(
			"expires later",
			json!({"label": "n", "scopes": ["read"], "ip_cidr": "127.0.0.0/16", "expires_in": "30d"}),
		),
		(
			"any network",
			json!({"label": "n", "scopes": ["read"], "expires_in": "1d"}),
		),
		(
			"a wider network",
			json!({"label": "n", "scopes": ["read"], "ip_cidr": "0.0.0.0/0", "expires_in": "1d"}),
		),
	] {
		let (status, _, reply) =
			call(&world.state, "POST", "/api/v1/keys", &limited, Some(body)).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {reply}");
		assert!(
			reply.to_string().contains("reaches further than itself"),
			"{what}: {reply}"
		);
		assert!(!labels(&world).contains(&"n".to_string()), "{what}");
	}
	// Inside both limits it makes the key, which proves the pinned key works
	// from where the requests come.
	let (status, _, reply) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		&limited,
		Some(
			json!({"label": "inside", "scopes": ["read"], "ip_cidr": "127.0.0.0/16", "expires_in": "1d"}),
		),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
}

#[tokio::test]
async fn a_key_lists_and_revokes_only_the_keys_it_could_have_made() {
	let world = world();
	let (_, _, listing) = call(&world.state, "GET", "/api/v1/keys", MAKER_A, None).await;
	let shown: Vec<&str> = listing["keys"]
		.as_array()
		.unwrap()
		.iter()
		.map(|row| row["label"].as_str().unwrap())
		.collect();
	// The key bound to `ann` is one it could have made: `ann` is inside its domain.
	assert_eq!(shown, ["bound", "maker-a", "of-a"], "{listing}");
	let (_, _, all) = call(&world.state, "GET", "/api/v1/keys", token(), None).await;
	assert_eq!(all["keys"].as_array().unwrap().len(), 7);
	// Another tenant's key, a key with more, and one that is not there are the same.
	let mut answers = Vec::new();
	for label in ["of-b", "everything", "maker", "nobody"] {
		let (status, _, body) = call(
			&world.state,
			"DELETE",
			&format!("/api/v1/keys/{label}"),
			MAKER_A,
			None,
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert_eq!(labels(&world).len(), 7, "nothing was revoked");
	let (status, _, _) = call(&world.state, "DELETE", "/api/v1/keys/of-a", MAKER_A, None).await;
	assert_eq!(status, StatusCode::OK);
}

/// The key that asks is looked at again when the new one is written: one
/// revoked a moment ago makes nothing.
#[tokio::test]
async fn a_key_revoked_in_the_file_makes_nothing_even_if_the_server_has_not_noticed() {
	let world = world();
	let mut store = crate::api::ApiKeyStore::open(world.dir.path()).unwrap();
	store.remove("maker").unwrap();
	let (status, _, body) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		MAKER,
		Some(json!({"label": "late", "scopes": ["read"]})),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(!labels(&world).contains(&"late".to_string()));
	let (status, _, _) = call(&world.state, "DELETE", "/api/v1/keys/of-a", MAKER, None).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(labels(&world).contains(&"of-a".to_string()));
}

#[tokio::test]
async fn the_file_has_a_cap_for_keys_made_by_keys_and_none_for_the_operator() {
	let world = world();
	let mut store = crate::api::ApiKeyStore::open(world.dir.path()).unwrap();
	for n in 0..600 {
		store
			.add(key(
				&format!("filler-{n}"),
				&format!("filler-secret-{n}"),
				&["read"],
				&[],
			))
			.unwrap();
	}
	let (status, _, body) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		MAKER,
		Some(json!({"label": "more", "scopes": ["read"]})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	let (status, _, _) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		token(),
		Some(json!({"label": "more", "scopes": ["read"]})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
}
