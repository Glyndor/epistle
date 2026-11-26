//! The queue is administered by the domain the server assigned to an entry
//! when it queued it, not by the address the message says it comes from.

use axum::http::StatusCode;

use super::base::{TOKEN, request};
use super::fixtures::{queue_ids, queue_message, tenant_key, world};
use super::*;

#[tokio::test]
async fn queue_tenant_owner_is_not_the_sender() {
	let world = world();
	// Mail from tenant A's address that a mailbox of tenant B forwarded:
	// the entry is B's, whoever the message says it is from.
	let forwarded = queue_message(world.state.spool(), "alice@a.test", Some("b.test"));
	// And one the server assigned to no domain at all.
	let unowned = queue_message(world.state.spool(), "alice@a.test", None);
	let app = router(world.state.clone());

	let (status, own) = request(&app, "GET", "/api/v1/queue", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		queue_ids(&own),
		[world.alice_entry.to_string()],
		"only what the server assigned to tenant A"
	);
	for id in [forwarded, unowned] {
		let (status, _) = request(
			&app,
			"DELETE",
			&format!("/api/v1/queue/{id}"),
			Some(tenant_key()),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "entry {id}");
		assert!(world.state.spool().load(id).is_ok(), "entry {id} stays");
	}
	// The operator's token still reaches everything.
	let (_, all) = request(&app, "GET", "/api/v1/queue", Some(TOKEN.as_str())).await;
	assert_eq!(queue_ids(&all).len(), 5);
}

#[tokio::test]
async fn queue_tenant_owner_still_lets_a_tenant_cancel_its_own() {
	let world = world();
	let own = queue_message(
		world.state.spool(),
		"someone@elsewhere.test",
		Some("a.test"),
	);
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{own}"),
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}
