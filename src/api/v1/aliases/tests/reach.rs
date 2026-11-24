//! Role addresses, sub-address tags, and the aliases whose members, senders or
//! accounts reach outside a key's domains: what a confined key is neither
//! shown nor allowed to change.

use super::fixture::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn create(world: &World, key: &str, body: Value) -> (StatusCode, Value) {
	call(world, "POST", "/api/v1/aliases", key, Some(body)).await
}

fn account_of(name: &str, addresses: &[&str]) -> String {
	let list: Vec<String> = addresses
		.iter()
		.map(|address| format!("{address:?}"))
		.collect();
	format!(
		"[[accounts]]\nname = {name:?}\naddresses = [{}]\npassword_hash = \"{HASH}\"\n\n",
		list.join(", ")
	)
}

fn message(body: &Value) -> String {
	body["error"]["message"].as_str().unwrap_or("").to_string()
}

#[tokio::test]
async fn role_addresses_are_not_for_a_key() {
	let world = world();
	for local in [
		"postmaster",
		"Abuse",
		"hostmaster",
		"webmaster",
		"security",
		"noc",
	] {
		let (status, body) = create(
			&world,
			TENANT_A,
			json!({"alias":format!("{local}@a.example"),"members":["ann@a.example"]}),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{local}: {body}");
		assert!(message(&body).contains("role address"), "{local}: {body}");
	}
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn the_alias_of_a_role_address_cannot_be_removed_through_the_route() {
	let world = world_with(
		"[[alias]]\naddress = \"postmaster@a.example\"\nmembers = [\"ann@a.example\"]\n",
	);
	for key in [TENANT_A, ALL] {
		let (status, body) = call(
			&world,
			"DELETE",
			"/api/v1/aliases/postmaster@a.example",
			key,
			None,
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
		assert!(message(&body).contains("role address"), "{body}");
	}
	assert!(world.disk().is_none(), "nothing was written");
	let (_, listed) = call(&world, "GET", "/api/v1/aliases", ALL, None).await;
	assert!(
		listed["aliases"]
			.as_array()
			.unwrap()
			.iter()
			.any(|row| row["address"] == "postmaster@a.example")
	);
}

#[tokio::test]
async fn an_alias_of_another_tenant_in_part_is_removed_with_the_answer_of_a_missing_one() {
	let world = world_with(
		"[[alias]]\naddress = \"mixed@a.example\"\nmembers = [\"ann@a.example\", \"bob@b.example\"]\n\n\
		 [[alias]]\naddress = \"sent@a.example\"\nmembers = [\"ann@a.example\"]\nsenders = [\"bob@b.example\"]\n",
	);
	let (missing_status, missing) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/ghost@a.example",
		TENANT_A,
		None,
	)
	.await;
	assert_eq!(missing_status, StatusCode::NOT_FOUND);
	for address in ["mixed@a.example", "sent@a.example"] {
		let (status, body) = call(
			&world,
			"DELETE",
			&format!("/api/v1/aliases/{address}"),
			TENANT_A,
			None,
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
		assert_eq!(
			message(&body).replace(address, "x"),
			message(&missing).replace("ghost@a.example", "x")
		);
	}
	assert!(world.disk().is_none(), "nothing was written");
	let (status, _) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/mixed@a.example",
		ALL,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_senders_of_an_alias_are_inside_the_key_s_domains_or_the_alias_is_not_listed() {
	let world = world_with(
		"[[alias]]\naddress = \"sent@a.example\"\nmembers = [\"ann@a.example\"]\nsenders = [\"bob@b.example\"]\n",
	);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", TENANT_A, None).await;
	let text = body.to_string();
	assert!(
		!text.contains("sent@a.example") && !text.contains("bob@b.example"),
		"{text}"
	);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", ALL, None).await;
	assert!(body.to_string().contains("sent@a.example"));
}

#[tokio::test]
async fn a_tag_in_an_alias_address_is_refused_through_the_route_with_or_without_the_account() {
	let world = world();
	for alias in ["ann+shop@a.example", "nobody+shop@a.example"] {
		let (status, body) = create(
			&world,
			TENANT_A,
			json!({"alias":alias,"members":["abe@a.example"]}),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
		assert!(message(&body).contains("tagged form"), "{body}");
	}
	let (status, body) = create(
		&world,
		TENANT_A,
		json!({"alias":"admin+x@a.example","members":["abe@a.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert!(message(&body).contains("role address"), "{body}");
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn an_alias_whose_member_account_reaches_outside_the_key_s_domains_is_neither_listed_nor_removable()
 {
	let world = world_with(&format!(
		"{}[[alias]]\naddress = \"split@a.example\"\nmembers = [\"dave@a.example\"]\n",
		account_of("dave", &["dave@a.example", "dave@b.example"])
	));
	let (_, body) = call(&world, "GET", "/api/v1/aliases", TENANT_A, None).await;
	assert!(!body.to_string().contains("split@a.example"), "{body}");
	assert!(!body.to_string().contains("dave@b.example"), "{body}");
	let (status, _) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/split@a.example",
		TENANT_A,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(world.disk().is_none());
	let (_, body) = call(&world, "GET", "/api/v1/aliases", ALL, None).await;
	assert!(body.to_string().contains("split@a.example"));
}
