//! `SieveScript/set` (RFC 9661 section 2.4): create, update, destroy and
//! every refusal.

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{app, call_as_alice, download, store, upload};
use super::tests::TOKEN;
use crate::managesieve::store::{MAX_SCRIPT_BYTES, MAX_SCRIPTS};

const KEEP: &[u8] = b"keep;\r\n";

/// `SieveScript/set` for alice with `args` merged in.
async fn set(app: &axum::Router, args: Value) -> Value {
	let mut full = json!({"accountId": "alice"});
	full.as_object_mut()
		.expect("object")
		.extend(args.as_object().expect("object").clone());
	call_as_alice(app, "SieveScript/set", full).await
}

async fn blob(app: &axum::Router, script: &[u8]) -> String {
	upload(app, TOKEN.as_str(), "alice", script).await
}

/// Create `name` through JMAP and return its id.
async fn create(app: &axum::Router, name: &str, script: &[u8]) -> String {
	let blob = blob(app, script).await;
	let response = set(
		app,
		json!({"create": {"c": {"name": name, "blobId": blob}}}),
	)
	.await;
	response[1]["created"]["c"]["id"]
		.as_str()
		.unwrap_or_else(|| panic!("created: {response}"))
		.to_string()
}

#[tokio::test]
async fn a_script_is_created_from_an_uploaded_blob() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = blob(&app, b"require \"fileinto\";\r\nfileinto \"Junk\";\r\n").await;
	let response = set(
		&app,
		json!({"create": {"a": {"name": "junk", "blobId": blob}}}),
	)
	.await;
	assert_eq!(response[0], "SieveScript/set");
	let created = &response[1]["created"]["a"];
	let id = created["id"].as_str().expect("id");
	assert_eq!(created["name"], "junk");
	assert_eq!(created["isActive"], false);
	assert_eq!(created["blobId"], format!("sieve-{id}-1"));
	assert_eq!(response[1]["notCreated"], json!({}));
	// ManageSieve sees the script, with the content as uploaded.
	let s = store(dir.path(), "alice");
	assert_eq!(
		s.get("junk").expect("get"),
		"require \"fileinto\";\r\nfileinto \"Junk\";\r\n"
	);
	// The state moved, and /get reports the same one.
	assert_ne!(response[1]["oldState"], response[1]["newState"]);
	let get = call_as_alice(&app, "SieveScript/get", json!({"accountId": "alice"})).await;
	assert_eq!(get[1]["state"], response[1]["newState"]);
	// And the blob downloads.
	let path = format!(
		"/jmap/download/alice/{}/junk.siv",
		created["blobId"].as_str().expect("blob")
	);
	assert_eq!(
		download(&app, TOKEN.as_str(), &path).await.2,
		b"require \"fileinto\";\r\nfileinto \"Junk\";\r\n"
	);
}

#[tokio::test]
async fn a_script_without_a_name_gets_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = blob(&app, KEEP).await;
	let response = set(
		&app,
		json!({"create": {"a": {"name": null, "blobId": blob}, "b": {"blobId": blob}}}),
	)
	.await;
	let names: Vec<&str> = ["a", "b"]
		.iter()
		.map(|c| response[1]["created"][c]["name"].as_str().expect("name"))
		.collect();
	assert!(
		names
			.iter()
			.all(|n| n.starts_with("script-") && n.len() == 15),
		"{names:?}"
	);
	assert_ne!(names[0], names[1]);
	assert_eq!(store(dir.path(), "alice").list().expect("list").len(), 2);
}

#[tokio::test]
async fn a_name_that_is_taken_is_already_exists_with_the_existing_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let existing = store(dir.path(), "alice")
		.create("work", "discard;\r\n")
		.expect("managesieve");
	let blob = blob(&app, KEEP).await;
	let response = set(
		&app,
		json!({"create": {"a": {"name": "work", "blobId": blob}}}),
	)
	.await;
	assert_eq!(response[1]["created"], json!({}));
	assert_eq!(
		response[1]["notCreated"]["a"],
		json!({"type": "alreadyExists", "existingId": existing.id})
	);
	assert_eq!(
		store(dir.path(), "alice").get("work").expect("get"),
		"discard;\r\n",
		"not overwritten"
	);
	assert_eq!(response[1]["oldState"], response[1]["newState"]);
}

#[tokio::test]
async fn a_script_the_store_refuses_is_not_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let huge = format!("keep;\r\n#{}\r\n", "x".repeat(MAX_SCRIPT_BYTES));
	let cases: Vec<(Vec<u8>, Value)> = vec![
		(
			b"keep;\r\nif if\r\n".to_vec(),
			json!({"type": "invalidSieve", "description": "line 2: expected '{'"}),
		),
		(
			b"require \"enotify\";\r\nkeep;".to_vec(),
			json!({"type": "invalidSieve", "description": "extension \"enotify\" is not supported"}),
		),
		(
			vec![0xff, 0xfe],
			json!({"type": "invalidSieve", "description": "script is not valid UTF-8"}),
		),
		(huge.into_bytes(), json!({"type": "tooLarge"})),
	];
	for (script, expected) in cases {
		let blob = blob(&app, &script).await;
		let response = set(
			&app,
			json!({"create": {"a": {"name": "bad", "blobId": blob}}}),
		)
		.await;
		assert_eq!(response[1]["notCreated"]["a"], expected);
	}
	assert!(store(dir.path(), "alice").list().expect("list").is_empty());
}

#[tokio::test]
async fn a_malformed_create_says_which_property() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = blob(&app, KEEP).await;
	let long = "n".repeat(201);
	for (spec, expected) in [
		(
			json!({"name": "a/b", "blobId": blob}),
			json!({"type": "invalidProperties", "properties": ["name"]}),
		),
		(
			json!({"name": "a\u{2028}b", "blobId": blob}),
			json!({"type": "invalidProperties", "properties": ["name"]}),
		),
		(
			json!({"name": long, "blobId": blob}),
			json!({"type": "invalidProperties", "properties": ["name"]}),
		),
		(
			json!({"name": "", "blobId": blob}),
			json!({"type": "invalidProperties", "properties": ["name"]}),
		),
		(
			json!({"name": 5, "blobId": blob}),
			json!({"type": "invalidProperties", "properties": ["name"]}),
		),
		(
			json!({"name": "ok"}),
			json!({"type": "invalidProperties", "properties": ["blobId"]}),
		),
		(
			json!({"name": "ok", "blobId": 7}),
			json!({"type": "invalidProperties", "properties": ["blobId"]}),
		),
		(
			json!({"name": "ok", "blobId": blob, "isActive": true}),
			json!({"type": "invalidProperties", "properties": ["isActive"]}),
		),
		(
			json!({"name": "ok", "blobId": blob, "id": "mine"}),
			json!({"type": "invalidProperties", "properties": ["id"]}),
		),
		(
			json!({"name": "ok", "blobId": "0190e9d2-7b1c-7000-8000-000000000000"}),
			json!({"type": "blobNotFound", "notFound": ["0190e9d2-7b1c-7000-8000-000000000000"]}),
		),
		(json!("not an object"), json!({"type": "invalidProperties"})),
	] {
		let response = set(&app, json!({"create": {"a": spec.clone()}})).await;
		assert_eq!(response[1]["notCreated"]["a"], expected, "{spec}");
	}
	assert!(store(dir.path(), "alice").list().expect("list").is_empty());
}

#[tokio::test]
async fn the_script_count_limit_is_over_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	for index in 0..MAX_SCRIPTS - 1 {
		s.create(&format!("s{index}"), "keep;\r\n").expect("fill");
	}
	let blob = blob(&app, KEEP).await;
	let response = set(&app, json!({"create": {"a": {"name": "last", "blobId": blob}, "b": {"name": "one-too-many", "blobId": blob}}})).await;
	let outcomes = [&response[1]["created"]["a"], &response[1]["created"]["b"]];
	assert_eq!(
		outcomes.iter().filter(|o| o.is_object()).count(),
		1,
		"exactly one fits"
	);
	let refused = ["a", "b"]
		.iter()
		.find_map(|c| response[1]["notCreated"].get(c))
		.expect("one refused");
	assert_eq!(refused, &json!({"type": "overQuota"}));
	assert_eq!(s.list().expect("list").len(), MAX_SCRIPTS);
}

#[tokio::test]
async fn an_update_renames_and_replaces_the_content() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let id = create(&app, "work", KEEP).await;
	let blob = blob(&app, b"discard;\r\n").await;
	let response = set(
		&app,
		json!({"update": {id.clone(): {"name": "main", "blobId": blob}}}),
	)
	.await;
	assert_eq!(
		response[1]["updated"][&id],
		json!({"blobId": format!("sieve-{id}-2")})
	);
	let s = store(dir.path(), "alice");
	assert_eq!(s.get("main").expect("get"), "discard;\r\n");
	assert!(s.get("work").is_err());
	let renamed = set(&app, json!({"update": {id.clone(): {"name": "final"}}})).await;
	assert_eq!(renamed[1]["updated"][&id], Value::Null);
	assert_eq!(s.get("final").expect("get"), "discard;\r\n");
}

#[tokio::test]
async fn an_update_that_cannot_be_applied_changes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let a = create(&app, "a", KEEP).await;
	let b = create(&app, "b", KEEP).await;
	let good = blob(&app, b"discard;\r\n").await;
	let bad = blob(&app, b"if if").await;
	for (patch, expected) in [
		(
			json!({"name": "b", "blobId": good}),
			json!({"type": "alreadyExists", "existingId": b}),
		),
		(
			json!({"blobId": bad}),
			json!({"type": "invalidSieve", "description": "line 1: expected '{'"}),
		),
		(
			json!({"isActive": true}),
			json!({"type": "invalidProperties", "properties": ["isActive"]}),
		),
		(
			json!({"id": "x"}),
			json!({"type": "invalidProperties", "properties": ["id"]}),
		),
		(
			json!({"name": null}),
			json!({"type": "invalidProperties", "properties": ["name"]}),
		),
		(json!({"name/extra": "x"}), json!({"type": "invalidPatch"})),
		(json!("name"), json!({"type": "invalidPatch"})),
	] {
		let response = set(&app, json!({"update": {a.clone(): patch.clone()}})).await;
		assert_eq!(response[1]["notUpdated"][&a], expected, "{patch}");
	}
	let missing = set(&app, json!({"update": {"nope": {"name": "x"}}})).await;
	assert_eq!(
		missing[1]["notUpdated"]["nope"],
		json!({"type": "notFound"})
	);
	assert_eq!(
		store(dir.path(), "alice").get("a").expect("untouched"),
		"keep;\r\n"
	);
}

#[tokio::test]
async fn destroying_removes_a_script_but_never_the_active_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let work = create(&app, "work", KEEP).await;
	let draft = create(&app, "draft", KEEP).await;
	store(dir.path(), "alice")
		.set_active(Some("work"))
		.expect("activate");
	let response = set(
		&app,
		json!({"destroy": [work.clone(), draft.clone(), "nope"]}),
	)
	.await;
	assert_eq!(response[1]["destroyed"], json!([draft]));
	assert_eq!(
		response[1]["notDestroyed"][&work],
		json!({"type": "sieveIsActive"})
	);
	assert_eq!(
		response[1]["notDestroyed"]["nope"],
		json!({"type": "notFound"})
	);
	assert_eq!(store(dir.path(), "alice").list().expect("list").len(), 1);
	// Deactivated first, in a call of its own, it can go.
	set(&app, json!({"onSuccessDeactivateScript": true})).await;
	let gone = set(&app, json!({"destroy": [work.clone()]})).await;
	assert_eq!(gone[1]["destroyed"], json!([work]));
}

#[tokio::test]
async fn if_in_state_guards_the_whole_call() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = blob(&app, KEEP).await;
	let stale = set(
		&app,
		json!({"ifInState": "999", "create": {"a": {"name": "x", "blobId": blob}}}),
	)
	.await;
	assert_eq!(stale[0], "error");
	assert_eq!(stale[1]["type"], "stateMismatch");
	assert!(store(dir.path(), "alice").list().expect("list").is_empty());
	let state =
		call_as_alice(&app, "SieveScript/get", json!({"accountId": "alice"})).await[1]["state"]
			.clone();
	let fresh = set(
		&app,
		json!({"ifInState": state, "create": {"a": {"name": "x", "blobId": blob}}}),
	)
	.await;
	assert_eq!(fresh[0], "SieveScript/set");
	assert!(fresh[1]["created"]["a"].is_object());
}

#[tokio::test]
async fn malformed_arguments_are_invalid_arguments() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for args in [
		json!({"create": []}),
		json!({"update": "x"}),
		json!({"destroy": {"a": 1}}),
		json!({"destroy": [1]}),
		json!({"onSuccessActivateScript": 5}),
		json!({"onSuccessDeactivateScript": "yes"}),
	] {
		let response = set(&app, args.clone()).await;
		assert_eq!(response[0], "error", "{args}");
		assert_eq!(response[1]["type"], "invalidArguments", "{args}");
	}
}

#[tokio::test]
async fn more_objects_than_maxobjectsinset_is_refused_whole() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = blob(&app, KEEP).await;
	let create: serde_json::Map<String, Value> = (0..501)
		.map(|n| {
			(
				format!("c{n}"),
				json!({"name": format!("s{n}"), "blobId": blob}),
			)
		})
		.collect();
	let response = set(&app, json!({"create": create})).await;
	assert_eq!(response[1]["type"], "requestTooLarge");
	assert!(store(dir.path(), "alice").list().expect("list").is_empty());
}

#[tokio::test]
async fn a_script_keeps_its_id_when_managesieve_renames_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let id = create(&app, "work", KEEP).await;
	store(dir.path(), "alice")
		.rename("work", "renamed")
		.expect("managesieve rename");
	let blob = blob(&app, b"discard;\r\n").await;
	let response = set(&app, json!({"update": {id.clone(): {"blobId": blob}}})).await;
	assert!(response[1]["updated"].get(&id).is_some(), "{response}");
	assert_eq!(
		store(dir.path(), "alice").get("renamed").expect("get"),
		"discard;\r\n"
	);
}

#[tokio::test]
async fn an_empty_script_can_be_created_as_it_can_over_managesieve() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = blob(&app, b"").await;
	let response = set(
		&app,
		json!({"create": {"a": {"name": "empty", "blobId": blob}}}),
	)
	.await;
	assert!(response[1]["created"]["a"]["id"].is_string(), "{response}");
	assert_eq!(store(dir.path(), "alice").get("empty").expect("get"), "");
}
