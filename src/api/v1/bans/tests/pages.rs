//! The listing is paged: never unbounded, ordered by subject, and resumed by
//! the subject the page before ended on.

use std::sync::Arc;

use axum::http::StatusCode;

use super::fixture::*;
use crate::antispam::bans::operator::tests::fake::FakeAdmin;

fn crowded(count: usize) -> World {
	let store = Arc::new(FakeAdmin::default());
	for n in 0..count {
		store.preload_ban(&format!("ip:203.0.113.{n}"), u64::MAX / 2);
	}
	build(store, true)
}

async fn page(world: &World, query: &str) -> (StatusCode, serde_json::Value) {
	call(world, "GET", &format!("/api/v1/bans{query}"), BANNER, None).await
}

fn subjects(page: &serde_json::Value) -> Vec<String> {
	page["bans"]
		.as_array()
		.expect("bans")
		.iter()
		.map(|row| row["subject"].as_str().expect("subject").to_string())
		.collect()
}

#[tokio::test]
async fn the_pages_together_are_the_whole_list_in_order_with_nothing_twice() {
	let world = crowded(23);
	let mut seen = Vec::new();
	let mut cursor = String::new();
	let mut pages = 0;
	loop {
		let query = if cursor.is_empty() {
			"?limit=5".to_string()
		} else {
			format!("?limit=5&cursor={}", cursor.replace(':', "%3A"))
		};
		let (status, reply) = page(&world, &query).await;
		assert_eq!(status, StatusCode::OK, "{reply}");
		assert!(subjects(&reply).len() <= 5, "{reply}");
		seen.extend(subjects(&reply));
		pages += 1;
		match reply["next_cursor"].as_str() {
			Some(next) => cursor = next.to_string(),
			None => break,
		}
		assert!(pages < 20, "the paging does not end");
	}
	assert_eq!(pages, 5);
	let mut expected = world.store.ban_subjects();
	expected.sort();
	assert_eq!(seen, expected);
}

#[tokio::test]
async fn a_page_is_cut_to_the_ceiling_and_zero_is_refused() {
	let world = crowded(30);
	let (status, reply) = page(&world, "?limit=0").await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
	let (status, reply) = page(&world, "?limit=1000000").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		subjects(&reply).len(),
		30,
		"under the ceiling every ban fits"
	);
	let big = crowded(600);
	let (_, reply) = page(&big, "?limit=1000000").await;
	assert_eq!(subjects(&reply).len(), 500, "{}", reply["next_cursor"]);
	assert!(reply["next_cursor"].is_string());
	let (_, reply) = page(&big, "").await;
	assert_eq!(subjects(&reply).len(), 100, "the default page");
}

#[tokio::test]
async fn bans_that_ended_are_not_listed() {
	let store = Arc::new(FakeAdmin::default());
	store.preload_ban("ip:203.0.113.1", 1);
	store.preload_ban("ip:203.0.113.2", u64::MAX / 2);
	let world = build(store, true);
	let (_, reply) = page(&world, "").await;
	assert_eq!(subjects(&reply), ["ip:203.0.113.2"]);
}
