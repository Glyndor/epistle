//! What a key tries that it must not get: another tenant's domain, members
//! that are not its own or not local, addresses that collide, role addresses,
//! odd spellings and bodies of the wrong size or shape. Each refusal leaves
//! the state file as it was, and a confined key cannot tell what does not
//! exist from what is not its own.

use super::fixture::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn create(world: &World, key: &str, body: Value) -> (StatusCode, Value) {
	call(world, "POST", "/api/v1/aliases", key, Some(body)).await
}

fn message(body: &Value) -> String {
	body["error"]["message"].as_str().unwrap_or("").to_string()
}

#[tokio::test]
async fn a_member_that_is_not_a_local_account_is_refused_with_one_answer() {
	let world = world();
	let mut answers = Vec::new();
	for member in [
		"someone@elsewhere.example",
		"ghost@a.example",
		"bob@b.example",
		"ann@a.example.evil.test",
	] {
		let (status, body) = create(
			&world,
			TENANT_A,
			json!({"alias":"x@a.example","members":[member]}),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{member}: {body}");
		answers.push(message(&body).replace(member, "MEMBER"));
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn an_unconfined_key_may_use_members_of_every_domain_but_never_external_ones() {
	let world = world();
	let (status, body) = create(
		&world,
		ALL,
		json!({"alias":"all@a.example","members":["ann@a.example","bob@b.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let (status, body) = create(
		&world,
		ALL,
		json!({"alias":"out@a.example","members":["ann@a.example","friend@remote.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(world.disk().unwrap().aliases.len(), 3);
}

#[tokio::test]
async fn a_confined_key_cannot_reach_a_domain_that_is_not_its_own() {
	let world = world();
	let (hosted_status, hosted) = create(
		&world,
		TENANT_A,
		json!({"alias":"x@b.example","members":["ann@a.example"]}),
	)
	.await;
	let (unhosted_status, unhosted) = create(
		&world,
		TENANT_A,
		json!({"alias":"x@nowhere.example","members":["ann@a.example"]}),
	)
	.await;
	let (alias_status, alias_domain) = create(
		&world,
		TENANT_A,
		json!({"alias":"x@alias.example","members":["ann@a.example"]}),
	)
	.await;
	assert_eq!(hosted_status, StatusCode::BAD_REQUEST);
	assert_eq!((hosted_status, &hosted), (unhosted_status, &unhosted));
	assert_eq!((hosted_status, &hosted), (alias_status, &alias_domain));
	let (status, body) = create(
		&world,
		ELSEWHERE,
		json!({"alias":"x@a.example","members":["ann@a.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn a_remove_of_another_tenants_alias_is_as_absent_as_one_that_does_not_exist() {
	let world = world();
	let (other_status, other) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/crew@b.example",
		TENANT_A,
		None,
	)
	.await;
	let (missing_status, missing) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/ghost@b.example",
		TENANT_A,
		None,
	)
	.await;
	assert_eq!(other_status, StatusCode::NOT_FOUND);
	assert_eq!(other_status, missing_status);
	assert_eq!(
		message(&other).replace("crew@", "x@"),
		message(&missing).replace("ghost@", "x@")
	);
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn an_address_that_something_already_holds_cannot_be_an_alias() {
	let world = world();
	for (alias, holder) in [
		("ann@a.example", "an account"),
		("team@a.example", "exists"),
	] {
		let (status, body) = create(
			&world,
			TENANT_A,
			json!({"alias":alias,"members":["abe@a.example"]}),
		)
		.await;
		assert!(
			status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT,
			"{alias}: {body}"
		);
		assert!(
			message(&body).contains(holder.rsplit(' ').next().unwrap()),
			"{alias}: {body}"
		);
	}
	assert!(world.disk().is_none());
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
async fn odd_spellings_are_one_form_or_a_refusal() {
	let world = world();
	for alias in [
		"te\u{0}am@a.example",
		"tea\nm@a.example",
		"te am@a.example",
		"x@a.example\r\nBcc: y@b.example",
		"x\u{2028}@a.example",
		"",
		"no-at-sign",
		"x@xn--a.example",
	] {
		let (status, body) = create(
			&world,
			TENANT_A,
			json!({"alias":alias,"members":["ann@a.example"]}),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{alias:?}: {body}");
	}
	let (status, body) = create(
		&world,
		TENANT_A,
		json!({"alias":"Zed@A.example","members":["ANN@A.EXAMPLE"]}),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body["alias"]["address"], "zed@a.example");
	assert_eq!(world.disk().unwrap().aliases.len(), 3);
}

#[tokio::test]
async fn a_body_of_the_wrong_size_or_shape_is_refused_before_anything_is_written() {
	let world = world();
	let many: Vec<String> = (0..101).map(|n| format!("m{n}@a.example")).collect();
	let cases = [
		json!({"alias":"x@a.example"}),
		json!({"alias":"x@a.example","members":[]}),
		json!({"alias":"x@a.example","members":["ann@a.example"],"target_account":"ann"}),
		json!({"alias":"x@a.example","members":many}),
		json!({"alias":"x@a.example","members":["ann@a.example"],"hidden":false}),
		json!({"alias":"x@a.example","members":[7]}),
		json!({"alias":"x@a.example","members":["a".repeat(400)]}),
		json!({"alias":"a".repeat(400),"members":["ann@a.example"]}),
		json!({"members":["ann@a.example"]}),
	];
	for body in cases {
		let (status, answer) = call_text(
			&world,
			"POST",
			"/api/v1/aliases",
			TENANT_A,
			body.to_string(),
		)
		.await;
		assert!(
			status.is_client_error(),
			"{body}: {status} {}",
			String::from_utf8_lossy(&answer)
		);
	}
	for broken in ["", "{", "[]", "null", "\"x\""] {
		let (status, _) = call_text(
			&world,
			"POST",
			"/api/v1/aliases",
			TENANT_A,
			broken.to_string(),
		)
		.await;
		assert!(status.is_client_error(), "{broken:?}: {status}");
	}
	let huge =
		json!({"alias":"x@a.example","members":["ann@a.example"],"padding":"x".repeat(32 * 1024)});
	let (status, _) = call_text(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		huge.to_string(),
	)
	.await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn a_target_account_of_another_tenant_looks_like_one_that_does_not_exist() {
	let world = world();
	let (other_status, other) = create(
		&world,
		TENANT_A,
		json!({"alias":"x@a.example","target_account":"bob"}),
	)
	.await;
	let (missing_status, missing) = create(
		&world,
		TENANT_A,
		json!({"alias":"x@a.example","target_account":"ghost"}),
	)
	.await;
	assert_eq!(other_status, StatusCode::BAD_REQUEST);
	assert_eq!((other_status, &other), (missing_status, &missing));
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
async fn a_tagged_form_of_an_account_address_is_refused_through_the_route() {
	let world = world();
	let (status, body) = create(
		&world,
		TENANT_A,
		json!({"alias":"ann+shop@a.example","members":["abe@a.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert!(message(&body).contains("tagged form"), "{body}");
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
