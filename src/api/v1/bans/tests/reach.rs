//! What a key cannot do to the store as a whole: use up the room of the
//! bans, cover more than it may with many networks, or lift what it could
//! not have made.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;
use crate::antispam::bans::operator::{
	API_MAX_ALLOW_NETWORKS, API_MAX_BAN_NETWORKS, API_MAX_MANUAL_BANS,
};

/// The bans the listeners raised on their own fill the table; a key can still ban.
#[tokio::test]
async fn automatic_bans_do_not_stop_a_key_from_banning() {
	let world = world();
	for n in 0..API_MAX_MANUAL_BANS + 50 {
		world
			.store
			.preload_ban(&format!("account:user{n}@example.org"), u64::MAX / 2);
	}
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{reply}");
}

#[tokio::test]
async fn the_manual_bans_of_a_key_have_a_cap() {
	let world = world();
	for n in 0..API_MAX_MANUAL_BANS {
		world.store.preload_manual(
			&format!("ip:2001:db8:{:x}:{:x}::1", n / 250, n % 250),
			u64::MAX / 2,
		);
	}
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "203.0.113.9"})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{reply}");
}

/// Many networks of a middling size, each allowed by itself, would cover
/// the address space in the end.
#[tokio::test]
async fn a_key_cannot_ban_or_allow_many_networks() {
	let world = world();
	for n in 0..API_MAX_BAN_NETWORKS {
		let net = format!("10.{}.{}.0/24", n / 250, n % 250);
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans",
			BANNER,
			Some(json!({"target": net})),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{net}: {reply}");
	}
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "192.0.2.0/24"})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{reply}");
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans",
		BANNER,
		Some(json!({"target": "192.0.2.9"})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::CREATED,
		"an address is not a network: {reply}"
	);
	for n in 0..API_MAX_ALLOW_NETWORKS {
		let net = format!("172.{}.{}.0/24", 16 + n / 250, n % 250);
		let (status, reply) = call(
			&world,
			"POST",
			"/api/v1/bans/allow",
			BANNER,
			Some(json!({"cidr": net})),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{net}: {reply}");
	}
	let (status, reply) = call(
		&world,
		"POST",
		"/api/v1/bans/allow",
		BANNER,
		Some(json!({"cidr": "198.51.100.0/24"})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{reply}");
}

/// What the operator banned or allowed with a wide block stays until the
/// operator lifts it.
#[tokio::test]
async fn a_key_cannot_lift_a_block_wider_than_it_may_name() {
	let world = world();
	world.store.preload_manual("cidr:10.0.0.0/8", u64::MAX / 2);
	world.store.allow_entries(["172.16.0.0/12".to_string()]);
	let (status, reply) = call(
		&world,
		"DELETE",
		"/api/v1/bans/cidr%3A10.0.0.0%2F8",
		BANNER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
	let (status, reply) = call(&world, "DELETE", "/api/v1/bans/10.0.0.0%2F8", BANNER, None).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
	let (status, reply) = call(
		&world,
		"DELETE",
		"/api/v1/bans/allow/172.16.0.0%2F12",
		BANNER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
	assert_eq!(world.store.ban_subjects(), ["cidr:10.0.0.0/8"]);
	assert_eq!(world.store.allowed(), ["172.16.0.0/12"]);
}
