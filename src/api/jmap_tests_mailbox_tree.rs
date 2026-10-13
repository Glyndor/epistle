//! JMAP Mailbox objects over nested folders (RFC 8621 §2): `name` is the
//! last level, `parentId` the id of the folder above, and Mailbox/set takes
//! `parentId` on create and update.

use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use serde_json::{Value, json};

async fn call(app: &axum::Router, method: &str, args: Value) -> Value {
	let req = json!({
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [[method, args, "m"]],
	});
	let (_, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	body["methodResponses"][0][1].clone()
}

async fn mailbox(app: &axum::Router, id: &str) -> Value {
	let reply = call(
		app,
		"Mailbox/get",
		json!({"accountId": "alice", "ids": [id]}),
	)
	.await;
	reply["list"][0].clone()
}

fn setup() -> (tempfile::TempDir, axum::Router) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	(dir, app)
}

#[tokio::test]
async fn a_child_created_under_a_parent_reports_its_parent_and_last_level() {
	let (_dir, app) = setup();
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {
			"p": {"name": "Work"},
			"c": {"name": "Project", "parentId": "#p"},
		}}),
	)
	.await;
	assert_eq!(reply["created"]["p"]["id"], "Work", "{reply}");
	assert_eq!(reply["created"]["c"]["id"], "Work/Project", "{reply}");
	let child = mailbox(&app, "Work/Project").await;
	assert_eq!(child["name"], "Project");
	assert_eq!(child["parentId"], "Work");
	assert_eq!(child["myRights"]["mayCreateChild"], true);
	let parent = mailbox(&app, "Work").await;
	assert_eq!(parent["name"], "Work");
	assert!(parent["parentId"].is_null());
}

#[tokio::test]
async fn names_are_utf8_and_cannot_hold_the_delimiter() {
	let (dir, app) = setup();
	call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {"p": {"name": "Work"}}}),
	)
	.await;
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {
			"ok": {"name": "Año", "parentId": "Work"},
			"slash": {"name": "a/b"},
			"orphan": {"name": "x", "parentId": "Missing"},
		}}),
	)
	.await;
	assert_eq!(reply["created"]["ok"]["id"], "Work/A&APE-o", "{reply}");
	assert!(
		dir.path()
			.join("accounts/alice/folders/Work&AC8-A&APE-o")
			.is_dir()
	);
	assert_eq!(mailbox(&app, "Work/A&APE-o").await["name"], "Año");
	for cid in ["slash", "orphan"] {
		assert_eq!(
			reply["notCreated"][cid]["type"], "invalidProperties",
			"{cid}: {reply}"
		);
	}
}

#[tokio::test]
async fn update_moves_a_mailbox_with_parent_id_and_keeps_it_on_rename() {
	let (_dir, app) = setup();
	call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {
			"p": {"name": "Work"},
			"c": {"name": "Project", "parentId": "#p"},
		}}),
	)
	.await;
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "update": {"Work/Project": {"name": "Plan"}}}),
	)
	.await;
	assert!(
		reply["notUpdated"]
			.as_object()
			.is_none_or(|map| map.is_empty()),
		"{reply}"
	);
	assert_eq!(mailbox(&app, "Work/Plan").await["parentId"], "Work");
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "update": {"Work/Plan": {"parentId": null}}}),
	)
	.await;
	assert!(
		reply["notUpdated"]
			.as_object()
			.is_none_or(|map| map.is_empty()),
		"{reply}"
	);
	assert!(mailbox(&app, "Plan").await["parentId"].is_null());
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "update": {"Work": {"parentId": "Plan"}}}),
	)
	.await;
	assert!(
		reply["notUpdated"]
			.as_object()
			.is_none_or(|map| map.is_empty()),
		"{reply}"
	);
	assert_eq!(mailbox(&app, "Plan/Work").await["parentId"], "Plan");
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "update": {"Plan": {"parentId": "Plan/Work"}}}),
	)
	.await;
	assert_eq!(
		reply["notUpdated"]["Plan"]["type"], "invalidProperties",
		"{reply}"
	);
}

#[tokio::test]
async fn destroying_a_parent_with_children_is_refused() {
	let (_dir, app) = setup();
	call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {
			"p": {"name": "Work"},
			"c": {"name": "Project", "parentId": "#p"},
		}}),
	)
	.await;
	let reply = call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "destroy": ["Work"]}),
	)
	.await;
	assert_eq!(
		reply["notDestroyed"]["Work"]["type"], "mailboxHasChild",
		"{reply}"
	);
}

#[tokio::test]
async fn the_rest_api_lists_each_mailbox_with_its_parent() {
	let (_dir, app) = setup();
	call(
		&app,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {
			"p": {"name": "Work"},
			"c": {"name": "Project", "parentId": "#p"},
		}}),
	)
	.await;
	let (_, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/mailboxes",
		Some(TOKEN.as_str()),
	)
	.await;
	assert!(
		body["mailboxes"]
			.as_array()
			.expect("names")
			.iter()
			.any(|name| name == "Work/Project"),
		"{body}"
	);
	let tree = body["tree"].as_array().expect("tree");
	assert!(
		tree.contains(&json!({"id": "Work/Project", "name": "Project", "parent_id": "Work"})),
		"{body}"
	);
	assert!(
		tree.contains(&json!({"id": "Work", "name": "Work", "parent_id": null})),
		"{body}"
	);
}
