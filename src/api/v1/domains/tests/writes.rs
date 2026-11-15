//! Mutations use durable state and do not directly publish live state.

use super::fixture::*;
use crate::domain::state::{Change, DomainsFile, StoredRole, edit};
use axum::http::StatusCode;
use serde_json::{Value, json};

pub(super) async fn call(
	world: &World,
	method: &str,
	path: &str,
	key: &str,
	body: Option<Value>,
) -> (StatusCode, Value) {
	crate::api::tests::base::request_with_body(
		&crate::api::router(world.state.clone()),
		method,
		path,
		Some(key),
		body,
	)
	.await
}

pub(super) fn disk(world: &World) -> DomainsFile {
	DomainsFile::read(&crate::domain::state::path(world.state.data_dir()))
		.unwrap()
		.unwrap()
}

pub(super) fn loaded(world: &World) -> crate::config::Config {
	crate::config::Config::load(&world._dir.path().join("mail.toml")).unwrap()
}

#[tokio::test]
async fn domain_add_and_remove_write_only_data_and_leave_reload_to_the_watcher() {
	let world = world();
	let config_path = world._dir.path().join("mail.toml");
	let before = std::fs::read(&config_path).unwrap();
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/domains",
		WRITER,
		Some(json!({"domain":" New.Example ","role":"receive-only"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(
		body,
		json!({"changed":true,"domain":"new.example","reload":"watcher"})
	);
	let file = disk(&world);
	let added = file.domain("new.example").unwrap();
	assert_eq!(added.role, StoredRole::ReceiveOnly);
	assert!(added.srs_secret.is_some());
	assert_eq!(std::fs::read(&config_path).unwrap(), before);
	assert!(
		!world.state.domains().contains(&"new.example".into()),
		"the handler did not reload"
	);
	let live = world.state.live_domains().unwrap();
	live.reload::<DomainsFile>(&file.render().unwrap()).unwrap();
	assert!(
		world.state.domains().contains(&"new.example".into()),
		"watcher reload publishes it"
	);
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/NEW.EXAMPLE",
		WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(disk(&world).domain("new.example").is_none());
	assert_eq!(std::fs::read(config_path).unwrap(), before);
}

#[tokio::test]
async fn domain_role_limits_and_switches_share_the_cli_commit_and_keep_other_entries() {
	let world = world();
	let before = loaded(&world);
	let edit = Change::Set {
		name: "a.example".into(),
		role: Some(StoredRole::ReceiveOnly),
		quota: Some(Some(2048)),
		submission_rate: Some(Some(3)),
	};
	let expected = edit::preview(&before, &edit).unwrap();
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/domains/A.EXAMPLE",
		WRITER,
		Some(json!({"role":"receive-only","quota":2048,"submission_rate":3})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(disk(&world), expected.after);
	let config = loaded(&world);
	assert_eq!(config.domain_quotas["a.example"], 2048);
	assert_eq!(config.domain_submission_limits["a.example"], 3);
	assert_eq!(config.receive_only_domains, ["a.example"]);
	assert!(config.disabled_domains.contains(&"b.example".into()));
	for suffix in ["disable", "enable"] {
		let path = format!("/api/v1/domains/a.example/{suffix}");
		let (status, body) = call(&world, "POST", &path, CONFINED, None).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		assert_eq!(
			disk(&world).domain("a.example").unwrap().role,
			StoredRole::ReceiveOnly
		);
	}
	// A confined key still sets the role of its own domain.
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/domains/a.example",
		CONFINED,
		Some(json!({"role":"full"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		disk(&world).domain("a.example").unwrap().role,
		StoredRole::Full
	);
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/domains/a.example",
		WRITER,
		Some(json!({"role":"receive-only","quota":null,"submission_rate":null})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let config = loaded(&world);
	assert!(!config.domain_quotas.contains_key("a.example"));
	assert!(!config.domain_submission_limits.contains_key("a.example"));
	assert_eq!(config.receive_only_domains, ["a.example"]);
}

#[tokio::test]
async fn domain_alias_writes_use_disk_even_before_reload_and_preserve_other_aliases() {
	let world = world();
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/domains/A.EXAMPLE/aliases",
		WRITER,
		Some(json!({"alias":"New-Alias.Example"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(disk(&world).aliases["new-alias.example"], "a.example");
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/a.example/aliases/NEW-ALIAS.EXAMPLE",
		WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(disk(&world).aliases.len(), 1);
	assert_eq!(disk(&world).aliases["alias.example"], "a.example");
}

#[cfg(unix)]
fn identity(world: &World) -> (u64, u32, std::time::SystemTime, Vec<u8>) {
	use std::os::unix::fs::MetadataExt;
	let path = crate::domain::state::path(world.state.data_dir());
	let metadata = std::fs::metadata(&path).unwrap();
	(
		metadata.ino(),
		metadata.mode() & 0o777,
		metadata.modified().unwrap(),
		std::fs::read(path).unwrap(),
	)
}

#[cfg(unix)]
#[tokio::test]
async fn domain_no_ops_succeed_without_creating_or_replacing_a_state_file() {
	let world = world();
	let path = crate::domain::state::path(world.state.data_dir());
	for (method, path, body) in [
		("POST", "/api/v1/domains/a.example/enable", None),
		("POST", "/api/v1/domains/b.example/disable", None),
		(
			"PUT",
			"/api/v1/domains/a.example",
			Some(json!({"role":"full","quota":1000,"submission_rate":7})),
		),
	] {
		let (status, body) = call(&world, method, path, WRITER, body).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		assert_eq!(body["changed"], false);
		assert_eq!(body["reload"], "none");
	}
	assert!(!path.exists(), "no-op must not create domains.toml");
	edit::seed(&loaded(&world)).unwrap();
	let before = identity(&world);
	assert_eq!(before.1, 0o600);
	for _ in 0..2 {
		let (status, body) = call(
			&world,
			"PUT",
			"/api/v1/domains/a.example",
			WRITER,
			Some(json!({"quota":1000,"submission_rate":7})),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
		assert_eq!(
			identity(&world),
			before,
			"inode, permissions, mtime and bytes must stay"
		);
	}
}

#[tokio::test]
async fn last_enabled_domain_and_in_use_refusals_match_the_cli_rules() {
	let world = world_with("[[listeners]]\nkind = 'smtp'\nport = 2525\n");
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/domains/xn--bcher-kva.example/disable",
		WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let before = disk(&world);
	let config = loaded(&world);
	for (method, path, change) in [
		(
			"POST",
			"/api/v1/domains/a.example/disable",
			Change::SetEnabled {
				name: "a.example".into(),
				enabled: false,
			},
		),
		(
			"DELETE",
			"/api/v1/domains/a.example",
			Change::Remove {
				name: "a.example".into(),
			},
		),
		(
			"DELETE",
			"/api/v1/domains/b.example",
			Change::Remove {
				name: "b.example".into(),
			},
		),
	] {
		let refusal = edit::preview(&config, &change).unwrap_err().to_string();
		let (status, body) = call(&world, method, path, WRITER, None).await;
		assert_eq!(status, StatusCode::CONFLICT, "{body}");
		assert_eq!(body["error"]["message"], refusal);
		assert_eq!(disk(&world), before);
	}
}
