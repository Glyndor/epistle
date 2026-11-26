//! The writes: banning, lifting, and the allow list.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

#[tokio::test]
async fn a_ban_lasts_a_day_unless_told_and_is_listed() {
	let world = world();
	let before = super::super::now();
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
	assert_eq!(reply["target"], "203.0.113.9");
	assert_eq!(reply["changed"], true);
	let until = reply["until"].as_u64().expect("until");
	assert!(
		(before + 86_400..=before + 86_410).contains(&until),
		"{reply}"
	);
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.0/24", "for": "90m"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
	assert_eq!(reply["target"], "203.0.113.0/24");
	let (_, listing) = call(&world, "GET", "/api/v1/bans", BANNER, None).await;
	let subjects: Vec<&str> = listing["bans"]
		.as_array()
		.expect("bans")
		.iter()
		.map(|row| row["subject"].as_str().expect("subject"))
		.collect();
	assert_eq!(subjects, ["cidr:203.0.113.0/24", "ip:203.0.113.9"]);
	assert_eq!(listing["bans"][0]["reason"], "manual ban");
}

#[tokio::test]
async fn banning_again_moves_the_end_and_a_lifted_ban_is_gone() {
	let world = world();
	call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9", "for": "1h"})),
	)
	.await;
	let (_, again) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9", "for": "2h"})),
	)
	.await;
	assert_eq!(world.store.ban_subjects(), ["ip:203.0.113.9"]);
	assert_eq!(
		world.store.ban_until("ip:203.0.113.9"),
		again["until"].as_u64()
	);
	let (status, lifted) = call(&world, "DELETE", "/api/v1/bans/203.0.113.9", BANNER, None).await;
	assert_eq!(status, StatusCode::OK, "{lifted}");
	assert_eq!(lifted["bans"], 1);
	assert_eq!(lifted["target"], "203.0.113.9");
	let (status, missing) = call(&world, "DELETE", "/api/v1/bans/203.0.113.9", BANNER, None).await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
	assert_eq!(missing["error"]["code"], "not_found");
}

/// The subjects the listeners ban on, written as `ban list` prints them and
/// percent-encoded in the path.
#[tokio::test]
async fn a_pair_an_account_and_a_network_ban_are_lifted_by_their_subject() {
	let world = crate::api::v1::bans::tests::fixture::build(
		std::sync::Arc::new(
			crate::antispam::bans::operator::tests::fake::FakeAdmin::with(
				&[
					(
						"pair:alice@example.org|203.0.113.9",
						"too many failures",
						u64::MAX / 2,
					),
					(
						"account:alice@example.org",
						"too many failures",
						u64::MAX / 2,
					),
					("cidr:203.0.113.0/24", "manual ban", u64::MAX / 2),
				],
				&[("pair:alice@example.org|203.0.113.9", 3)],
			),
		),
		true,
	);
	for (path, bans, failures) in [
		("pair%3Aalice%40example.org%7C203.0.113.9", 1, 1),
		("account%3Aalice%40example.org", 1, 0),
		("cidr%3A203.0.113.0%2F24", 1, 0),
	] {
		let (status, lifted) = call(
			&world,
			"DELETE",
			&format!("/api/v1/bans/{path}"),
			BANNER,
			None,
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{path}: {lifted}");
		assert_eq!(
			(lifted["bans"].as_u64(), lifted["failures"].as_u64()),
			(Some(bans), Some(failures)),
			"{path}"
		);
	}
	assert!(world.store.ban_subjects().is_empty());
}

#[tokio::test]
async fn an_allow_listed_address_cannot_be_banned() {
	let world = world();
	world.store.allow_entries(["203.0.113.0/24".to_string()]);
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9"})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{reply}");
	assert!(world.store.ban_subjects().is_empty());
}

/// A key is held to a narrower reach than the operator.
#[tokio::test]
async fn a_key_cannot_ban_or_allow_a_block_wider_than_a_slash_sixteen() {
	let world = world();
	for wide in ["10.0.0.0/8", "10.0.0.0/15", "2001:db8::/31"] {
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans",
			BANNER,
			Some(json!({"target": wide})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{wide}: {reply}");
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans/allow",
			BANNER,
			Some(json!({"cidr": wide})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{wide}: {reply}");
	}
	for refused in ["0.0.0.0/0", "::/0"] {
		let (status, _) = call(
			&world,
			"POST",
			"/api/v1/bans",
			BANNER,
			Some(json!({"target": refused})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
		let (status, _) = call(
			&world,
			"POST",
			"/api/v1/bans/allow",
			BANNER,
			Some(json!({"cidr": refused})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
	}
	assert!(
		world.store.writes().is_empty(),
		"{:?}",
		world.store.writes()
	);
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "10.1.0.0/16"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
}

#[tokio::test]
async fn the_allow_list_is_listed_added_once_and_removed() {
	let world = world();
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans/allow",
		BANNER,
		Some(json!({"cidr": "10.1.2.3/16"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
	assert_eq!(reply["cidr"], "10.1.0.0/16", "stored in its canonical form");
	let (status, again) = call(
		&world,
		"POST",
		"/api/v1/bans/allow",
		BANNER,
		Some(json!({"cidr": "10.1.0.0/16"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{again}");
	assert_eq!(again["changed"], false);
	let (_, listing) = call(&world, "GET", "/api/v1/bans/allow", BANNER, None).await;
	assert_eq!(listing["allow"], json!(["10.1.0.0/16"]));
	let (status, gone) = call(
		&world,
		"DELETE",
		"/api/v1/bans/allow/10.1.0.0%2F16",
		BANNER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{gone}");
	let (status, missing) = call(
		&world,
		"DELETE",
		"/api/v1/bans/allow/10.1.0.0%2F16",
		BANNER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
}

/// A store that fails is a plain `500`: the answer carries nothing of the
/// database.
#[tokio::test]
async fn a_failing_store_answers_without_its_message() {
	let world = world();
	world.store.break_down();
	for (method, path, body) in [
		("GET", "/api/v1/bans", None),
		(
			"POST",
			"/api/v1/bans",
			Some(json!({"target": "203.0.113.9"})),
		),
		("GET", "/api/v1/bans/allow", None),
		("DELETE", "/api/v1/bans/203.0.113.9", None),
	] {
		let (status, reply) = call(&world, method, path, BANNER, body).await;
		assert_eq!(
			status,
			StatusCode::INTERNAL_SERVER_ERROR,
			"{method} {path}: {reply}"
		);
		let text = reply.to_string().to_lowercase();
		assert!(
			!text.contains("database") && !text.contains("connection"),
			"{text}"
		);
	}
}
