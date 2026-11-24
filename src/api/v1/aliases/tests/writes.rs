//! What a create and a remove do: the state file, the shape of the answer,
//! the dry run, the reload, and that the command and the route give the same
//! result.

use super::fixture::*;
use crate::aliases::edit::{self, NewAlias};
use crate::aliases::{AliasesFile, Change, Origin};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn a_create_writes_the_state_file_and_leaves_the_reload_to_the_watcher() {
	let world = world();
	let before = std::fs::read(world.config_path()).unwrap();
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		Some(
			json!({"alias":" Sales@A.Example ".trim(),"members":["ann@a.example","ABE@a.example"]}),
		),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body["changed"], true);
	assert_eq!(body["reload"], "watcher");
	assert_eq!(body["alias"]["address"], "sales@a.example");
	assert_eq!(
		body["alias"]["members"],
		json!(["ann@a.example", "abe@a.example"])
	);
	assert_eq!(body["alias"]["hidden"], true);
	let file = world.disk().expect("written");
	assert!(file.alias("sales@a.example").is_some());
	assert!(
		file.alias("team@a.example").is_some(),
		"the seed was copied in first"
	);
	assert_eq!(
		std::fs::read(world.config_path()).unwrap(),
		before,
		"mail.toml is not written"
	);
	let live = world.state.live_domains().unwrap();
	assert_eq!(live.current().alias.len(), 2, "the handler did not reload");
	live.reload::<AliasesFile>(&file.render().unwrap()).unwrap();
	assert_eq!(
		live.current().alias.len(),
		3,
		"the watcher's reload publishes it"
	);
}

#[tokio::test]
async fn a_target_account_stands_for_its_address_in_the_alias_domain() {
	let world = world();
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		Some(json!({"alias":"help@a.example","target_account":"abe"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body["alias"]["members"], json!(["abe@a.example"]));
}

#[tokio::test]
async fn a_dry_run_validates_and_writes_nothing() {
	let world = world();
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		Some(json!({"alias":"help@a.example","members":["abe@a.example"],"dry_run":true})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		(body["dry_run"].as_bool(), body["changed"].as_bool()),
		(Some(true), Some(false))
	);
	assert!(world.disk().is_none());
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		Some(json!({"alias":"help@a.example","members":["ghost@a.example"],"dry_run":true})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::BAD_REQUEST,
		"a dry run refuses what the write would: {body}"
	);
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/team@a.example?dry_run=true",
		TENANT_A,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		(body["dry_run"].as_bool(), body["changed"].as_bool()),
		(Some(true), Some(false))
	);
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn a_remove_drops_the_alias_and_a_second_one_finds_nothing() {
	let world = world();
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/TEAM@a.example",
		TENANT_A,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["alias"], "team@a.example");
	assert_eq!(body["changed"], true);
	assert!(world.disk().unwrap().alias("team@a.example").is_none());
	assert!(world.disk().unwrap().alias("crew@b.example").is_some());
	let (status, again) = call(
		&world,
		"DELETE",
		"/api/v1/aliases/team@a.example",
		TENANT_A,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{again}");
	assert_eq!(again["error"]["message"], "alias team@a.example not found");
}

#[tokio::test]
async fn an_alias_that_exists_is_a_conflict_with_the_text_of_the_command() {
	let world = world();
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		Some(json!({"alias":"team@a.example","members":["abe@a.example"]})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	let command = edit::preview(
		&world.state.live_domains().unwrap().current(),
		&Change::Add(NewAlias {
			address: "team@a.example".into(),
			members: vec!["abe@a.example".into()],
			senders: Vec::new(),
			list_id: None,
			hidden: true,
		}),
		&Origin::Operator,
	)
	.unwrap_err();
	assert_eq!(body["error"]["message"], command.to_string());
	assert!(world.disk().is_none());
}

#[tokio::test]
async fn the_command_and_the_route_make_the_same_alias() {
	let by_route = world();
	let (status, body) = call(
		&by_route,
		"POST",
		"/api/v1/aliases",
		ALL,
		Some(json!({"alias":"Mixed.Case@A.EXAMPLE","members":["ABE@a.example","bob@b.example","abe@A.example"]})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let by_command = world();
	edit::commit(
		&by_command.state.live_domains().unwrap().current(),
		&Change::Add(NewAlias {
			address: "Mixed.Case@A.EXAMPLE".into(),
			members: vec![
				"ABE@a.example".into(),
				"bob@b.example".into(),
				"abe@A.example".into(),
			],
			senders: Vec::new(),
			list_id: None,
			hidden: true,
		}),
		&Origin::Operator,
	)
	.unwrap();
	let (left, right) = (by_route.disk().unwrap(), by_command.disk().unwrap());
	assert_eq!(left.aliases, right.aliases);
	assert_eq!(left.render().unwrap(), right.render().unwrap());
}

#[tokio::test]
async fn the_caps_of_the_domain_apply_to_the_route_as_to_the_command() {
	let world = world_with("[limits]\nmax_aliases_per_domain = 1\n");
	let (status, body) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_A,
		Some(json!({"alias":"more@a.example","members":["abe@a.example"]})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert_eq!(body["error"]["code"], "limit_reached");
	assert!(
		body["error"]["message"]
			.as_str()
			.unwrap()
			.contains("domain a.example")
	);
	let (status, _) = call(
		&world,
		"POST",
		"/api/v1/aliases",
		TENANT_B,
		Some(json!({"alias":"more@b.example","members":["bob@b.example"]})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"b.example has its own alias already"
	);
}
