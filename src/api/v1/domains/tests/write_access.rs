//! Route-table witnesses: write scope, confinement and alias ownership.

use super::fixture::*;
use super::writes::{call, disk, loaded};
use crate::domain::state::{Change, edit};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn domain_creation_requires_an_unconfined_writer() {
	let world = world();
	for (key, domain) in [
		(CONFINED, "new.example"),
		(CONFINED, "a.example"),
		(READER, "new.example"),
		(SENDER, "new.example"),
	] {
		let (status, body) = call(
			&world,
			"POST",
			"/api/v1/domains",
			key,
			Some(json!({"domain":domain})),
		)
		.await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	}
	assert!(!crate::domain::state::path(world.state.data_dir()).exists());
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/domains",
		WRITER,
		Some(json!({"domain":"new.example"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn domain_writes_are_confined_to_the_keys_domains() {
	let world = world();
	for domain in ["B.EXAMPLE", "unknown.example"] {
		for (method, suffix, body) in [
			("DELETE", "", None),
			("PUT", "", Some(json!({"role":"send-only"}))),
			("POST", "/enable", None),
			("POST", "/disable", None),
		] {
			let path = format!("/api/v1/domains/{domain}{suffix}");
			let (status, body) = call(&world, method, &path, CONFINED, body).await;
			assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
			assert_eq!(body["error"]["message"], "no such domain");
		}
	}
	assert!(!crate::domain::state::path(world.state.data_dir()).exists());
	// Limits are the operator's: a confined key may not touch them, not even
	// to clear one, while an unconfined key may.
	for body in [
		json!({"quota":42}),
		json!({"quota":null}),
		json!({"submission_rate":1}),
		json!({"role":"send-only","submission_rate":null}),
	] {
		let (status, answer) = call(
			&world,
			"PUT",
			"/api/v1/domains/A.EXAMPLE",
			CONFINED,
			Some(body),
		)
		.await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
		assert!(!crate::domain::state::path(world.state.data_dir()).exists());
	}
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/domains/A.EXAMPLE",
		WRITER,
		Some(json!({"quota":42})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/a.example",
		CONFINED,
		None,
	)
	.await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"reached CLI's in-use check: {body}"
	);
	// This key also covers alias.example. Once the alias is gone, the
	// operator may host that name and the confined key may remove it.
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/a.example/aliases/alias.example",
		WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/domains",
		WRITER,
		Some(json!({"domain":"alias.example"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/alias.example",
		ALIAS_WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn domain_aliases_require_both_names_in_scope() {
	let world = world();
	for (target, alias) in [
		("b.example", "alias.example"),
		("ghost.example", "alias.example"),
		("a.example", "foreign.example"),
	] {
		let path = format!("/api/v1/domains/{target}/aliases");
		let (status, body) = call(
			&world,
			"POST",
			&path,
			ALIAS_WRITER,
			Some(json!({"alias":alias})),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
		let (status, body) = call(
			&world,
			"DELETE",
			&format!("{path}/{alias}"),
			ALIAS_WRITER,
			None,
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	}
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/a.example/aliases/alias.example",
		ALIAS_WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/domains/a.example/aliases",
		ALIAS_WRITER,
		Some(json!({"alias":"ALIAS.EXAMPLE"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn alias_removal_checks_the_fresh_target_while_the_watcher_is_behind() {
	let world = world();
	edit::commit(
		&loaded(&world),
		&Change::AliasRemove {
			alias: "alias.example".into(),
		},
	)
	.unwrap();
	edit::commit(
		&loaded(&world),
		&Change::AliasAdd {
			alias: "alias.example".into(),
			target: "b.example".into(),
		},
	)
	.unwrap();
	let before = disk(&world);
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/a.example/aliases/alias.example",
		ALIAS_WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	assert_eq!(disk(&world), before);
}

#[tokio::test]
async fn every_domain_mutation_needs_the_write_scope() {
	let world = world();
	for key in [READER, SENDER] {
		for (method, path, body) in [
			(
				"POST",
				"/api/v1/domains",
				Some(json!({"domain":"new.example"})),
			),
			("DELETE", "/api/v1/domains/a.example", None),
			("PUT", "/api/v1/domains/a.example", Some(json!({"quota":4}))),
			("POST", "/api/v1/domains/a.example/enable", None),
			("POST", "/api/v1/domains/a.example/disable", None),
			(
				"POST",
				"/api/v1/domains/a.example/aliases",
				Some(json!({"alias":"new.example"})),
			),
			(
				"DELETE",
				"/api/v1/domains/a.example/aliases/alias.example",
				None,
			),
		] {
			let (status, body) = call(&world, method, path, key, body).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
		}
	}
	assert!(!crate::domain::state::path(world.state.data_dir()).exists());
}
