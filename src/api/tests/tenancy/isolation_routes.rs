//! A confined key reaches only its own tenant's queue and suppression
//! lists.

use axum::http::StatusCode;
use serde_json::json;

use super::base::{TOKEN, request, request_with_body};
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

#[tokio::test]
async fn a_confined_key_cannot_add_to_the_global_suppression_list() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/suppression",
		Some(tenant_key()),
		Some(json!({"address": "intruder@elsewhere.test"})),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(
		!SuppressionList::open(world.state.data_dir())
			.expect("list")
			.is_suppressed("intruder@elsewhere.test")
	);
}

#[tokio::test]
async fn a_confined_key_can_add_inside_its_account() {
	let world = world();
	let app = router(world.state.clone());
	let address = "new-gone@elsewhere.test";
	let body = Some(json!({"address": address}));
	let (status, added) = request_with_body(
		&app,
		"POST",
		"/api/v1/suppression?account=alice",
		Some(tenant_key()),
		body.clone(),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(added["suppressed"], address);
	let list = SuppressionList::open(world.state.data_dir()).expect("list");
	assert!(list.is_suppressed_for("alice", address));
	assert!(list.is_suppressed_for("alice@a.test", address));
	assert!(!list.is_suppressed(address), "not the global list");
	assert!(!list.is_suppressed_for("carol", address));
	assert!(!list.is_suppressed_for("carol@b.test", address));

	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/suppression?account=carol",
		Some(tenant_key()),
		Some(json!({"address": "other-gone@elsewhere.test"})),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let list = SuppressionList::open(world.state.data_dir()).expect("list");
	assert!(!list.is_suppressed("other-gone@elsewhere.test"));
	assert!(!list.is_suppressed_for("carol", "other-gone@elsewhere.test"));
	assert!(!list.is_suppressed_for("carol@b.test", "other-gone@elsewhere.test"));
}
