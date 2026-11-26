//! Who may show and steer an entry, and what a key confined to a tenant sees.

use axum::http::StatusCode;

use super::fixture::*;

#[tokio::test]
async fn the_scopes_are_read_for_showing_and_write_for_changing() {
	let world = world();
	let id = world.mine;
	for (secret, method, path, expected) in [
		(READER, "GET", format!("/api/v1/queue/{id}"), StatusCode::OK),
		(
			WRITER,
			"GET",
			format!("/api/v1/queue/{id}"),
			StatusCode::FORBIDDEN,
		),
		(
			READER,
			"POST",
			format!("/api/v1/queue/{id}/hold"),
			StatusCode::FORBIDDEN,
		),
		(
			WRITER,
			"POST",
			format!("/api/v1/queue/{id}/hold"),
			StatusCode::OK,
		),
		(
			READER,
			"GET",
			"/api/v1/queue/destinations".to_string(),
			StatusCode::OK,
		),
		(
			WRITER,
			"GET",
			"/api/v1/queue/destinations".to_string(),
			StatusCode::FORBIDDEN,
		),
	] {
		let (status, body) = call(&world.state, method, &path, secret).await;
		assert_eq!(status, expected, "{method} {path}: {body}");
	}
}

/// An entry of another tenant is as absent as one that does not exist, for
/// showing and for every change, and nothing of it is changed.
#[tokio::test]
async fn another_tenants_entry_answers_as_one_that_does_not_exist() {
	let world = world();
	let absent = uuid::Uuid::now_v7();
	for suffix in ["", "/retry", "/hold", "/release"] {
		let method = if suffix.is_empty() { "GET" } else { "POST" };
		let foreign = call(
			&world.state,
			method,
			&format!("/api/v1/queue/{}{suffix}", world.theirs),
			TENANT_A,
		)
		.await;
		let none = call(
			&world.state,
			method,
			&format!("/api/v1/queue/{absent}{suffix}"),
			TENANT_A,
		)
		.await;
		assert_eq!(foreign.0, StatusCode::NOT_FOUND, "{suffix}: {}", foreign.1);
		assert_eq!(foreign, none, "{suffix}: the answer tells them apart");
	}
	let theirs = world
		.state
		.spool()
		.load_envelope(world.theirs)
		.expect("kept");
	assert!(theirs.held.is_none(), "another tenant's entry was held");
	let (status, _) = call(
		&world.state,
		"GET",
		&format!("/api/v1/queue/{}", world.mine),
		TENANT_A,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_bound_key_is_refused_and_the_destinations_are_for_an_unconfined_key() {
	let world = world();
	let (status, _) = call(
		&world.state,
		"GET",
		&format!("/api/v1/queue/{}", world.mine),
		BOUND,
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, body) = call(&world.state, "GET", "/api/v1/queue/destinations", TENANT_A).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let (status, body) = call(&world.state, "GET", "/api/v1/queue/destinations", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["destinations"], serde_json::json!([]));
}

#[tokio::test]
async fn names_that_are_not_an_entry_are_refused() {
	let world = world();
	for path in [
		"/api/v1/queue/not-a-uuid",
		"/api/v1/queue/..%2F..%2Fetc%2Fpasswd",
		"/api/v1/queue/00000000-0000-0000-0000-000000000000",
		"/api/v1/queue/not-a-uuid/hold",
	] {
		for (method, bearer) in [("GET", READER), ("POST", WRITER), ("GET", token())] {
			let (status, _) = call(&world.state, method, path, bearer).await;
			assert!(status.is_client_error(), "{method} {path}: {status}");
			assert_ne!(status, StatusCode::OK);
		}
	}
}

/// An entry belongs to the owner the server decided, not to the sender the
/// message names: mail written from a tenant's domain by a stranger, or owned
/// by another tenant, is not the tenant's, and a forward or a return is the
/// tenant's whatever its reverse-path says.
#[tokio::test]
async fn an_entry_belongs_to_its_owner_and_not_to_the_sender_it_names() {
	let world = world();
	for (what, id, reached) in [
		("an entry of the tenant", world.mine, true),
		("a forward without SRS", world.forward, true),
		("a forward with SRS", world.forward_srs, true),
		("a return with no sender", world.bounce, true),
		(
			"a return whose sender is another tenant's SRS address",
			world.srs_bounce,
			true,
		),
		(
			"mail from the tenant's domain with no owner",
			world.spoofed,
			false,
		),
		(
			"mail from the tenant's domain owned by another tenant",
			world.misowned,
			false,
		),
		("another tenant's entry", world.theirs, false),
	] {
		let (status, body) = call(
			&world.state,
			"GET",
			&format!("/api/v1/queue/{id}"),
			TENANT_A,
		)
		.await;
		let expected = if reached {
			StatusCode::OK
		} else {
			StatusCode::NOT_FOUND
		};
		assert_eq!(status, expected, "{what}: {body}");
		let (status, _) = call(
			&world.state,
			"POST",
			&format!("/api/v1/queue/{id}/hold"),
			TENANT_A,
		)
		.await;
		assert_eq!(status, expected, "{what} (hold)");
	}
	// The key with no confinement reaches every one of them.
	for id in [world.spoofed, world.misowned, world.forward, world.bounce] {
		let (status, _) = call(&world.state, "GET", &format!("/api/v1/queue/{id}"), READER).await;
		assert_eq!(status, StatusCode::OK);
	}
	let spoofed = world.state.spool().load_envelope(world.spoofed).unwrap();
	assert!(
		spoofed.held.is_none(),
		"an entry that is not the key's was held"
	);
}

/// The list and the removal decide as the detail routes do.
#[tokio::test]
async fn the_list_and_the_removal_decide_by_the_owner_too() {
	let world = world();
	let (_, page) = call(&world.state, "GET", "/api/v1/queue?limit=100", TENANT_A).await;
	let listed: Vec<String> = page["entries"]
		.as_array()
		.unwrap()
		.iter()
		.map(|entry| entry["id"].as_str().unwrap().to_string())
		.collect();
	for id in [
		world.mine,
		world.forward,
		world.forward_srs,
		world.bounce,
		world.srs_bounce,
	] {
		assert!(listed.contains(&id.to_string()), "{id} is the tenant's");
	}
	for id in [world.spoofed, world.misowned, world.theirs] {
		assert!(
			!listed.contains(&id.to_string()),
			"{id} is not the tenant's"
		);
		let (status, _) = call(
			&world.state,
			"DELETE",
			&format!("/api/v1/queue/{id}"),
			TENANT_A,
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND);
		assert!(
			world.state.spool().load_envelope(id).is_ok(),
			"{id} was removed"
		);
	}
}
