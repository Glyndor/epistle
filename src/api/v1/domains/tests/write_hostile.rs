//! Refusals match the shared CLI rules and never write partial changes.

use super::fixture::*;
use super::writes::{call, disk, loaded};
use crate::domain::state::{Change, StoredRole, edit};
use axum::http::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn unknown_domains_and_aliases_keep_the_cli_messages() {
	let world = world();
	for (method, path, body, expected) in [
		(
			"DELETE",
			"/api/v1/domains/ghost.example",
			None,
			"domain ghost.example is not configured",
		),
		(
			"PUT",
			"/api/v1/domains/ghost.example",
			Some(json!({"quota":3})),
			"domain ghost.example is not configured",
		),
		(
			"POST",
			"/api/v1/domains/ghost.example/enable",
			None,
			"domain ghost.example is not configured",
		),
		(
			"POST",
			"/api/v1/domains/ghost.example/disable",
			None,
			"domain ghost.example is not configured",
		),
		(
			"POST",
			"/api/v1/domains/ghost.example/aliases",
			Some(json!({"alias":"new.example"})),
			"domain alias target ghost.example is not a configured domain",
		),
		(
			"DELETE",
			"/api/v1/domains/a.example/aliases/ghost.example",
			None,
			"domain alias ghost.example is not declared",
		),
	] {
		let (status, body) = call(&world, method, path, WRITER, body).await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
		assert_eq!(body["error"]["message"], expected);
	}
	assert!(!crate::domain::state::path(world.state.data_dir()).exists());
}

#[tokio::test]
async fn already_hosted_and_alias_collisions_are_conflicts_without_writes() {
	let world = world();
	for (path, body, change) in [
		(
			"/api/v1/domains",
			json!({"domain":"a.example"}),
			Change::Add {
				name: "a.example".into(),
				role: StoredRole::Full,
				dkim: None,
				srs_secret: None,
			},
		),
		(
			"/api/v1/domains",
			json!({"domain":"alias.example"}),
			Change::Add {
				name: "alias.example".into(),
				role: StoredRole::Full,
				dkim: None,
				srs_secret: None,
			},
		),
		(
			"/api/v1/domains/a.example/aliases",
			json!({"alias":"alias.example"}),
			Change::AliasAdd {
				alias: "alias.example".into(),
				target: "a.example".into(),
			},
		),
		(
			"/api/v1/domains/a.example/aliases",
			json!({"alias":"b.example"}),
			Change::AliasAdd {
				alias: "b.example".into(),
				target: "a.example".into(),
			},
		),
	] {
		let expected = edit::preview(&loaded(&world), &change)
			.unwrap_err()
			.to_string();
		let (status, body) = call(&world, "POST", path, WRITER, Some(body)).await;
		assert_eq!(status, StatusCode::CONFLICT, "{body}");
		assert_eq!(body["error"]["message"], expected);
	}
	assert!(!crate::domain::state::path(world.state.data_dir()).exists());
}

pub(super) async fn raw(
	world: &World,
	method: &str,
	path: &str,
	body: Option<Value>,
) -> StatusCode {
	use axum::body::Body;
	use axum::http::{Request, header};
	use tower::ServiceExt;
	let request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {WRITER}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
		.unwrap();
	crate::api::router(world.state.clone())
		.oneshot(request)
		.await
		.unwrap()
		.status()
}

#[tokio::test]
async fn hostile_names_are_checked_for_every_domain_and_alias_input() {
	let world = world();
	for (name, encoded) in [
		("a.example.", "a.example."),
		("bücher.example", "b%C3%BCcher.example"),
		("a..example", "a..example"),
		("bad name.example", "bad%20name.example"),
		("bad\n.example", "bad%0A.example"),
		("../etc/passwd", "..%2Fetc%2Fpasswd"),
		("a\0.example", "a%00.example"),
		("-bad.example", "-bad.example"),
	] {
		let (status, body) = call(
			&world,
			"POST",
			"/api/v1/domains",
			WRITER,
			Some(json!({"domain":name})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{name:?}: {body}");
		let (status, body) = call(
			&world,
			"POST",
			"/api/v1/domains/a.example/aliases",
			WRITER,
			Some(json!({"alias":name})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{name:?}: {body}");
		for (method, suffix, body) in [
			("DELETE", "", None),
			("PUT", "", Some(json!({"role":"full"}))),
			("POST", "/enable", None),
			("POST", "/disable", None),
			("POST", "/aliases", Some(json!({"alias":"safe.example"}))),
		] {
			let path = format!("/api/v1/domains/{encoded}{suffix}");
			assert_eq!(
				raw(&world, method, &path, body).await,
				StatusCode::BAD_REQUEST,
				"{path}"
			);
		}
		let path = format!("/api/v1/domains/a.example/aliases/{encoded}");
		assert_eq!(
			raw(&world, "DELETE", &path, None).await,
			StatusCode::BAD_REQUEST,
			"{path}"
		);
	}
	for name in [
		String::new(),
		"a".repeat(254),
		format!("{}.example", "a".repeat(64)),
		"раураl.com".into(),
	] {
		let (status, _) = call(
			&world,
			"POST",
			"/api/v1/domains",
			WRITER,
			Some(json!({"domain":name})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST);
	}
	assert!(!crate::domain::state::path(world.state.data_dir()).exists());
	assert!(!world.state.data_dir().join("keys").exists());
}

#[tokio::test]
async fn invalid_limits_do_not_apply_the_role_and_null_clears_inherited_limits() {
	let world = world();
	edit::seed(&loaded(&world)).unwrap();
	let before = disk(&world);
	for (body, expected) in [
		(json!({"quota":-1}), StatusCode::UNPROCESSABLE_ENTITY),
		(json!({"quota":"1G"}), StatusCode::UNPROCESSABLE_ENTITY),
		(json!({"role":"disabled"}), StatusCode::UNPROCESSABLE_ENTITY),
		(json!({"unexpected":true}), StatusCode::UNPROCESSABLE_ENTITY),
		(
			json!({"submission_rate":4294967296_u64}),
			StatusCode::UNPROCESSABLE_ENTITY,
		),
		(json!({}), StatusCode::BAD_REQUEST),
		(
			json!({"role":"send-only","submission_rate":0}),
			StatusCode::BAD_REQUEST,
		),
		(
			json!({"role":"send-only","quota":9223372036854775808_u64}),
			StatusCode::BAD_REQUEST,
		),
	] {
		assert_eq!(
			raw(&world, "PUT", "/api/v1/domains/a.example", Some(body)).await,
			expected
		);
		assert_eq!(disk(&world), before);
	}
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/domains/a.example",
		WRITER,
		Some(json!({"quota":null})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let config = loaded(&world);
	assert!(!config.domain_quotas.contains_key("a.example"));
	assert_eq!(config.domain_submission_limits["a.example"], 7);
}

#[tokio::test]
async fn a_confined_key_is_not_told_which_other_tenants_use_the_domain() {
	let world = world_with(
		"[[alias]]\naddress = \"team@other.example\"\nmembers = [\"bob@a.example\"]\n\
		 [[tenant]]\nname = \"rival-tenant\"\ndomains = [\"a.example\"]\n",
	);
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/a.example",
		CONFINED,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert_eq!(body["error"]["message"], "domain is still in use");
	let text = body.to_string();
	for (case, foreign) in ["other.example", "rival-tenant", "bob@a.example"]
		.into_iter()
		.enumerate()
	{
		assert!(
			!text.contains(foreign),
			"the refusal leaked a name from another tenant (case {case})"
		);
	}
	let (status, body) = call(&world, "DELETE", "/api/v1/domains/a.example", WRITER, None).await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	let text = body["error"]["message"].as_str().unwrap();
	for detail in ["team@other.example", "rival-tenant"] {
		assert!(text.contains(detail), "{detail} missing: {text}");
	}
}
