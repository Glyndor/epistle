//! Adding and removing addresses: what is stored, what is refused, the caps of
//! the store and of a tenant, and the audit.

use axum::http::StatusCode;
use serde_json::json;
use tracing::instrument::WithSubscriber;

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
async fn an_address_is_added_in_lower_case_and_the_answer_says_what_was_done() {
	let world = world();
	let (status, body) = add(&world, token(), "alice", "Fresh@A.Test").await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body["result"], "saved");
	assert_eq!(body["action"], "address add");
	assert_eq!(body["account"], "alice");
	assert_eq!(body["address"], "fresh@a.test");
	assert!(addresses(&world, "alice").contains(&"fresh@a.test".to_string()));
}

#[tokio::test]
async fn a_taken_address_is_the_same_409_whoever_holds_it_and_changes_nothing() {
	let world = world();
	let mut answers = Vec::new();
	for address in [
		"alice@a.test",
		"bob@b.test",
		"bob+tag@b.test",
		"split@a.test",
	] {
		let (status, body) = add(&world, token(), "alice", address).await;
		assert_eq!(status, StatusCode::CONFLICT, "{address}: {body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert!(!answers[0].to_string().contains("bob"));
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
	assert_eq!(addresses(&world, "bob"), ["bob@b.test"]);
}

#[tokio::test]
async fn the_cap_of_the_store_is_a_409_and_leaves_the_account_as_it_was() {
	let world = world();
	for n in 0..2 {
		let (status, body) = add(&world, token(), "alice", &format!("more{n}@a.test")).await;
		assert_eq!(status, StatusCode::CREATED, "{body}");
	}
	let (status, body) = add(&world, token(), "alice", "one-too-many@a.test").await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert_eq!(addresses(&world, "alice").len(), 4);
}

#[tokio::test]
async fn an_address_goes_and_the_last_one_stays() {
	let world = world();
	let (status, body) = remove(&world, token(), "alice", "ALICE2@a.test").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["action"], "address remove");
	assert_eq!(addresses(&world, "alice"), ["alice@a.test"]);
	let (status, body) = remove(&world, token(), "alice", "alice@a.test").await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(addresses(&world, "alice"), ["alice@a.test"]);
	let (status, _) = remove(&world, token(), "alice", "alice2@a.test").await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "an address already gone");
}

#[tokio::test]
async fn every_change_is_audited_once_and_no_refusal_is() {
	let world = world();
	let capture = Capture::default();
	let subscriber = capture.dispatch();
	async {
		for (bearer, name, address) in [
			(READER, "alice", "a1@a.test"),
			(OF_A, "alice", "b1@b.test"),
			(OF_B, "alice", "a1@a.test"),
			(OF_ALICE, "alice", "a1@a.test"),
			(token(), "alice", "alice@a.test"),
			(token(), "nobody", "a1@a.test"),
		] {
			add(&world, bearer, name, address).await;
		}
		remove(&world, token(), "alice", "nope@a.test").await;
		remove(&world, token(), "bob", "bob@b.test").await;
		add(&world, OF_A, "alice", "kept@a.test").await;
		remove(&world, OF_A, "alice", "kept@a.test").await;
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.events();
	assert_eq!(
		capture.kinds(),
		["account.address_added", "account.address_removed"],
		"{events:?}"
	);
	assert_eq!(events[0]["key"], "of-a");
	assert_eq!(events[0]["domain"], "a.test");
	let text = format!("{events:?}");
	for hidden in ["kept@a.test", "alice@", OF_A, "a long enough password"] {
		assert!(!text.contains(hidden), "the audit carries {hidden}");
	}
}

/// Many requests for one address: one account has it, one line says so.
#[tokio::test]
async fn concurrent_requests_for_one_address_give_it_to_one_request() {
	let world = world();
	let capture = Capture::default();
	let dispatch = capture.dispatch();
	let mut tasks = tokio::task::JoinSet::new();
	for n in 0..12 {
		let state = world.state.clone();
		let name = if n % 2 == 0 { "alice" } else { "bob" };
		tasks.spawn(
			async move {
				call(
					&state,
					"POST",
					&format!("/api/v1/accounts/{name}/addresses"),
					token(),
					Some(json!({"address": "shared@a.test"})),
				)
				.await
				.0
			}
			.with_subscriber(dispatch.clone()),
		);
	}
	let mut created = 0;
	while let Some(status) = tasks.join_next().await {
		if status.unwrap() == StatusCode::CREATED {
			created += 1;
		}
	}
	assert_eq!(created, 1);
	let holders = ["alice", "bob"]
		.iter()
		.filter(|name| addresses(&world, name).contains(&"shared@a.test".to_string()))
		.count();
	assert_eq!(holders, 1, "one address, one account");
	assert_eq!(capture.events().len(), 1);
}

/// A tenant at its `max_accounts` takes no account it does not count already:
/// an address in its domains would make one more.
#[tokio::test]
async fn a_tenant_at_its_cap_takes_no_account_that_is_not_in_it_already() {
	let world = world();
	let (status, body) = add(&world, token(), "bob", "x@c.test").await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let (status, body) = add(&world, token(), "alice", "y@c.test").await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert!(body.to_string().contains("max_accounts"), "{body}");
	assert_eq!(
		addresses(&world, "alice"),
		["alice2@a.test", "alice@a.test"]
	);
	// The account that is in keeps adding, and one that leaves frees the place.
	let (status, body) = add(&world, token(), "bob", "z@c.test").await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	// An address in a tenant with no cap needs no place.
	let (status, _) = add(&world, token(), "alice", "free@a.test").await;
	assert_eq!(status, StatusCode::CREATED);
	// An unknown account is the store's own 404, not a refusal of the cap.
	let (status, _) = add(&world, token(), "nobody", "q@c.test").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Requests at once for the last place of a tenant: one account gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_for_the_last_place_of_a_tenant_give_it_to_one_account() {
	let world = world();
	for n in 0..8 {
		world
			.store
			.add(account(&format!("u{n}"), &[&format!("u{n}@a.test")]))
			.expect("account");
	}
	let mut tasks = tokio::task::JoinSet::new();
	for n in 0..8 {
		let state = world.state.clone();
		tasks.spawn(async move {
			call(
				&state,
				"POST",
				&format!("/api/v1/accounts/u{n}/addresses"),
				WRITER,
				Some(json!({"address": format!("v{n}@c.test")})),
			)
			.await
			.0
		});
	}
	let mut created = 0;
	while let Some(status) = tasks.join_next().await {
		match status.unwrap() {
			StatusCode::CREATED => created += 1,
			StatusCode::CONFLICT => {}
			other => panic!("unexpected {other}"),
		}
	}
	assert_eq!(created, 1);
	let inside = (0..8)
		.filter(|n| {
			addresses(&world, &format!("u{n}"))
				.iter()
				.any(|a| a.ends_with("@c.test"))
		})
		.count();
	assert_eq!(inside, 1, "one account in a tenant that holds one");
}
