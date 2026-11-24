//! Who may use the routes, and what a listing shows each of them.

use super::fixture::*;
use axum::http::StatusCode;

#[tokio::test]
async fn only_the_alias_scope_opens_the_routes() {
	let world = world();
	for (method, path, request) in [
		("GET", "/api/v1/aliases", None),
		(
			"POST",
			"/api/v1/aliases",
			Some(serde_json::json!({"alias":"x@a.example","members":["ann@a.example"]})),
		),
		("DELETE", "/api/v1/aliases/team@a.example", None),
	] {
		let (status, answer) = call(&world, method, path, READ_WRITE, request.clone()).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
		let (status, _) = call(&world, method, path, "not-a-key", request.clone()).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
		let (status, _) = call(&world, method, path, EXPIRED, request).await;
		assert_eq!(
			status,
			StatusCode::UNAUTHORIZED,
			"{method} {path} with an expired key"
		);
	}
	assert!(world.disk().is_none(), "no refused request wrote anything");
}

#[tokio::test]
async fn a_key_bound_to_an_account_is_turned_away() {
	let world = world();
	let (status, body) = call(&world, "GET", "/api/v1/aliases", BOUND, None).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let (status, _) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		BOUND,
		Some(serde_json::json!({"alias":"x@a.example","members":["ann@a.example"]})),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn a_listing_shows_a_key_its_own_domains_and_the_configured_token_everything() {
	let world = world();
	let (status, body) = call(&world, "GET", "/api/v1/aliases", token(), None).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(addresses(&body), ["crew@b.example", "team@a.example"]);
	let row = &body["aliases"][1];
	assert_eq!(row["members"], serde_json::json!(["ann@a.example"]));
	assert_eq!(row["enabled"], true);
	assert_eq!(row["hidden"], true);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", TENANT_A, None).await;
	assert_eq!(addresses(&body), ["team@a.example"]);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", TENANT_B, None).await;
	assert_eq!(addresses(&body), ["crew@b.example"]);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", ELSEWHERE, None).await;
	assert!(addresses(&body).is_empty());
}

#[tokio::test]
async fn the_filters_and_the_pages_follow_the_other_list_routes() {
	let world = world();
	let (_, body) = call(&world, "GET", "/api/v1/aliases?domain=B.Example", ALL, None).await;
	assert_eq!(addresses(&body), ["crew@b.example"]);
	let (_, body) = call(&world, "GET", "/api/v1/aliases?account=ann", ALL, None).await;
	assert_eq!(addresses(&body), ["team@a.example"]);
	let (_, first) = call(&world, "GET", "/api/v1/aliases?limit=1", ALL, None).await;
	assert_eq!(addresses(&first), ["crew@b.example"]);
	assert_eq!(first["next_cursor"], "crew@b.example");
	let (_, second) = call(
		&world,
		"GET",
		"/api/v1/aliases?limit=1&cursor=crew@b.example",
		ALL,
		None,
	)
	.await;
	assert_eq!(addresses(&second), ["team@a.example"]);
	assert!(second.get("next_cursor").is_none());
	for query in ["limit=0", "domain=not%20a%20domain"] {
		let (status, body) = call(
			&world,
			"GET",
			&format!("/api/v1/aliases?{query}"),
			ALL,
			None,
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
	}
}

#[tokio::test]
async fn a_confined_key_gets_one_answer_for_a_domain_or_an_account_that_is_not_its_own() {
	let world = world();
	let answer = |query: &'static str| {
		let world = &world;
		async move {
			call(
				world,
				"GET",
				&format!("/api/v1/aliases?{query}"),
				TENANT_A,
				None,
			)
			.await
		}
	};
	let (other_status, other) = answer("domain=b.example").await;
	let (missing_status, missing) = answer("domain=nowhere.example").await;
	assert_eq!((other_status, &other), (missing_status, &missing));
	assert_eq!(other_status, StatusCode::NOT_FOUND);
	let (other_status, other) = answer("account=bob").await;
	let (missing_status, missing) = answer("account=ghost").await;
	assert_eq!((other_status, &other), (missing_status, &missing));
	assert_eq!(other_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_alias_with_a_member_outside_the_key_s_domains_is_not_listed() {
	let world = world();
	let (status, _) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		token(),
		Some(
			serde_json::json!({"alias":"mixed@a.example","members":["ann@a.example","bob@b.example"]}),
		),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", TENANT_A, None).await;
	assert_eq!(addresses(&body), ["team@a.example"]);
	let (_, body) = call(&world, "GET", "/api/v1/aliases", ALL, None).await;
	assert_eq!(addresses(&body).len(), 3);
}

#[tokio::test]
async fn the_alias_scope_opens_the_alias_routes_and_nothing_else() {
	let world = world();
	for path in [
		"/api/v1/domains",
		"/api/v1/accounts",
		"/api/v1/status",
		"/api/v1/queue",
		"/api/v1/openapi.json",
	] {
		let (status, _) = call(&world, "GET", path, TENANT_A, None).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
	}
}
