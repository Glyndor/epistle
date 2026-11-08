//! A confined key reaches only its own tenant's queue and suppression
//! lists.

use axum::http::StatusCode;
use serde_json::json;

use super::base::{TOKEN, request};
use super::fixtures::{queue_ids, tenant_key, world};
use super::*;
use crate::queue::SuppressionList;

#[tokio::test]
async fn the_queue_lists_only_the_tenants_own_messages() {
	let world = world();
	let app = router(world.state.clone());
	let (status, body) = request(&app, "GET", "/api/v1/queue", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(queue_ids(&body), [world.alice_entry.to_string()]);
	let (_, all) = request(&app, "GET", "/api/v1/queue", Some(TOKEN.as_str())).await;
	assert_eq!(
		queue_ids(&all).len(),
		3,
		"the configured token sees all three"
	);
}

#[tokio::test]
async fn another_tenants_queue_entry_cannot_be_removed() {
	let world = world();
	let app = router(world.state.clone());
	for id in [world.carol_entry, world.null_path_entry] {
		let (status, _) = request(
			&app,
			"DELETE",
			&format!("/api/v1/queue/{id}"),
			Some(tenant_key()),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "entry {id}");
		assert!(
			world.state.spool().load(id).is_ok(),
			"entry {id} must stay queued"
		);
	}
	let own = world.alice_entry;
	let (status, _) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{own}"),
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_shared_suppression_list_is_not_for_a_confined_key() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(&app, "GET", "/api/v1/suppression", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/suppression/victim%40b.test",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (_, listed) = request(&app, "GET", "/api/v1/suppression", Some(TOKEN.as_str())).await;
	assert_eq!(listed["addresses"], json!(["victim@b.test"]));
}

#[tokio::test]
async fn an_account_suppression_list_follows_the_account_scope() {
	let world = world();
	let app = router(world.state.clone());
	let (status, own) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=alice",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(own["addresses"], json!(["alice-gone@elsewhere.test"]));
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=carol",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let path = "/api/v1/suppression/carol-gone%40elsewhere.test?account=carol";
	let (status, _) = request(&app, "DELETE", path, Some(tenant_key())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		SuppressionList::open(world.state.data_dir())
			.expect("list")
			.list_for("carol"),
		["carol-gone@elsewhere.test"]
	);
}
