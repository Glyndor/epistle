//! A confined key reaches only its own tenant's accounts, archive,
//! masked addresses, credentials and counters.

use axum::http::StatusCode;
use serde_json::json;

use super::base::{TOKEN, request, request_with_body};
use super::fixtures::{tenant_key, world};
use super::*;
use crate::test_support::fixtures;

#[tokio::test]
async fn masked_addresses_of_another_tenants_account_are_out_of_reach() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/accounts/carol/masked",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/carol/masked",
		Some(tenant_key()),
		Some(json!({"label": "evil"})),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		world.store.list_masked("carol").len(),
		1,
		"no alias was minted"
	);
	let address = world.store.list_masked("carol")[0].address.clone();
	let path = format!("/api/v1/accounts/carol/masked/{address}");
	let off = Some(json!({"enabled": false}));
	let (status, _) = request_with_body(&app, "PATCH", &path, Some(tenant_key()), off).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request(&app, "DELETE", &path, Some(tenant_key())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(
		world.store.list_masked("carol")[0].enabled,
		"the alias is untouched"
	);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(tenant_key()),
		Some(json!({"label": "shop"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn the_archive_of_another_tenants_account_is_out_of_reach() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/accounts/carol/archive",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let path = format!(
		"/api/v1/accounts/carol/archive/{}/restore",
		world.carol_archived
	);
	let (status, _) = request(&app, "POST", &path, Some(tenant_key())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, listed) = request(
		&app,
		"GET",
		"/api/v1/accounts/carol/archive",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		listed["entries"].as_array().expect("entries").len(),
		1,
		"still archived"
	);
}

#[tokio::test]
async fn credential_verification_does_not_confirm_another_tenants_password() {
	let world = world();
	let app = router(world.state.clone());
	let verify = |name: &str| Some(json!({"name": name, "password": fixtures::password()}));
	for name in ["carol", "carol@b.test"] {
		let (status, body) = request_with_body(
			&app,
			"POST",
			"/api/v1/auth/verify",
			Some(tenant_key()),
			verify(name),
		)
		.await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["valid"], false, "{name} is not this key's to check");
	}
	let (_, own) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(tenant_key()),
		verify("alice"),
	)
	.await;
	assert_eq!(own["valid"], true);
	let (_, any) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		verify("carol"),
	)
	.await;
	assert_eq!(any["valid"], true, "the configured token verifies anyone");
}

#[tokio::test]
async fn the_status_counters_cover_only_the_tenants_own_scope() {
	let world = world();
	let app = router(world.state.clone());
	let (status, own) = request(&app, "GET", "/api/v1/status", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(own["domains"], 1);
	assert_eq!(own["accounts"], 1);
	assert!(
		own.get("queue_size").is_none(),
		"the queue is shared: {own}"
	);
	let (_, all) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(all["domains"], 2);
	assert_eq!(all["accounts"], 2);
	assert_eq!(all["queue_size"], 3);
}

#[tokio::test]
async fn two_factor_and_display_name_of_another_tenants_account_are_out_of_reach() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"POST",
		"/api/v1/accounts/carol/totp",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/carol/totp",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(
		world
			.store
			.dynamic("carol")
			.expect("carol")
			.totp_secret
			.is_none()
	);
	let (status, _) = request_with_body(
		&app,
		"PUT",
		"/api/v1/accounts/carol/display_name",
		Some(tenant_key()),
		Some(json!({"display_name": "CEO"})),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		world.store.dynamic("carol").expect("carol").display_name,
		None
	);
}

#[tokio::test]
async fn an_account_name_held_by_another_tenant_answers_like_an_unusable_one() {
	let world = world();
	let app = router(world.state.clone());
	let create = |name: &str| {
		Some(json!({
			"name": name,
			"addresses": ["new@a.test"],
			"password": "correct horse battery staple",
		}))
	};
	let (taken_status, taken) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(tenant_key()),
		create("carol"),
	)
	.await;
	let (bad_status, bad) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(tenant_key()),
		create("Not A Name!"),
	)
	.await;
	assert_eq!(taken_status, bad_status);
	assert_eq!(
		taken, bad,
		"the answer must not say the name exists elsewhere"
	);
}
