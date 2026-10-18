//! `SieveScript/query` (RFC 9661 section 2.5).

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{ann_only, app, call, call_as_alice, store};

/// Three scripts: `alpha` (active), `Beta`, `gamma`.
fn seed(dir: &std::path::Path) -> Vec<String> {
	let s = store(dir, "alice");
	let ids: Vec<String> = ["alpha", "Beta", "gamma"]
		.iter()
		.map(|name| s.create(name, "keep;\r\n").expect("create").id)
		.collect();
	s.set_active(Some("alpha")).expect("activate");
	ids
}

async fn query(dir: &std::path::Path, args: Value) -> Value {
	let mut full = json!({"accountId": "alice"});
	full.as_object_mut()
		.expect("object")
		.extend(args.as_object().expect("object").clone());
	call_as_alice(&app(dir), "SieveScript/query", full).await
}

fn ids(response: &Value) -> Vec<String> {
	response[1]["ids"]
		.as_array()
		.unwrap_or_else(|| panic!("ids in {response}"))
		.iter()
		.map(|id| id.as_str().expect("string").to_string())
		.collect()
}

#[tokio::test]
async fn with_no_arguments_every_script_comes_back_by_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let all = seed(dir.path());
	let response = query(dir.path(), json!({})).await;
	assert_eq!(response[0], "SieveScript/query");
	// By name, byte order: "Beta" before "alpha" and "gamma".
	assert_eq!(
		ids(&response),
		vec![all[1].clone(), all[0].clone(), all[2].clone()]
	);
	assert_eq!(response[1]["position"], 0);
	assert_eq!(response[1]["canCalculateChanges"], false);
	assert!(response[1].get("total").is_none(), "total only when asked");
	let get = call_as_alice(
		&app(dir.path()),
		"SieveScript/get",
		json!({"accountId": "alice"}),
	)
	.await;
	assert_eq!(response[1]["queryState"], get[1]["state"]);
}

#[tokio::test]
async fn filters_by_name_and_by_active() {
	let dir = tempfile::tempdir().expect("tempdir");
	let all = seed(dir.path());
	let by_name = query(dir.path(), json!({"filter": {"name": "BETA"}})).await;
	assert_eq!(
		ids(&by_name),
		vec![all[1].clone()],
		"contains, ignoring case"
	);
	let active = query(dir.path(), json!({"filter": {"isActive": true}})).await;
	assert_eq!(ids(&active), vec![all[0].clone()]);
	let inactive = query(dir.path(), json!({"filter": {"isActive": false}})).await;
	assert_eq!(ids(&inactive), vec![all[1].clone(), all[2].clone()]);
	let both = query(
		dir.path(),
		json!({"filter": {"name": "a", "isActive": false}}),
	)
	.await;
	assert_eq!(ids(&both), vec![all[1].clone(), all[2].clone()]);
	let none = query(dir.path(), json!({"filter": {"name": "zzz"}})).await;
	assert_eq!(ids(&none), Vec::<String>::new());
}

#[tokio::test]
async fn sorts_by_name_or_by_active_in_either_direction() {
	let dir = tempfile::tempdir().expect("tempdir");
	let all = seed(dir.path());
	let down = query(
		dir.path(),
		json!({"sort": [{"property": "name", "isAscending": false}]}),
	)
	.await;
	assert_eq!(
		ids(&down),
		vec![all[2].clone(), all[0].clone(), all[1].clone()]
	);
	let active_first = query(
		dir.path(),
		json!({"sort": [{"property": "isActive", "isAscending": false}]}),
	)
	.await;
	assert_eq!(ids(&active_first)[0], all[0]);
	let active_last = query(
		dir.path(),
		json!({"sort": [{"property": "isActive"}, {"property": "name", "isAscending": false}]}),
	)
	.await;
	assert_eq!(
		ids(&active_last),
		vec![all[2].clone(), all[1].clone(), all[0].clone()]
	);
}

#[tokio::test]
async fn position_limit_anchor_and_total() {
	let dir = tempfile::tempdir().expect("tempdir");
	let all = seed(dir.path());
	let page = query(
		dir.path(),
		json!({"position": 1, "limit": 1, "calculateTotal": true}),
	)
	.await;
	assert_eq!(ids(&page), vec![all[0].clone()]);
	assert_eq!(page[1]["position"], 1);
	assert_eq!(page[1]["total"], 3);
	let from_end = query(dir.path(), json!({"position": -1})).await;
	assert_eq!(ids(&from_end), vec![all[2].clone()]);
	assert_eq!(from_end[1]["position"], 2);
	let anchored = query(dir.path(), json!({"anchor": all[0], "anchorOffset": 1})).await;
	assert_eq!(ids(&anchored), vec![all[2].clone()]);
	let missing = query(dir.path(), json!({"anchor": "nope"})).await;
	assert_eq!(missing[1]["type"], "anchorNotFound");
	let beyond = query(dir.path(), json!({"position": 99})).await;
	assert_eq!(ids(&beyond), Vec::<String>::new());
}

#[tokio::test]
async fn what_the_server_cannot_do_is_said_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed(dir.path());
	for (args, kind) in [
		(
			json!({"filter": {"operator": "OR", "conditions": []}}),
			"unsupportedFilter",
		),
		(json!({"filter": {"blobId": "x"}}), "unsupportedFilter"),
		(json!({"sort": [{"property": "blobId"}]}), "unsupportedSort"),
		(
			json!({"sort": [{"property": "name", "collation": "i;octet"}]}),
			"unsupportedSort",
		),
		(json!({"filter": {"name": 1}}), "invalidArguments"),
		(json!({"filter": {"isActive": "yes"}}), "invalidArguments"),
		(json!({"sort": "name"}), "invalidArguments"),
		(json!({"position": "1"}), "invalidArguments"),
		(json!({"limit": -1}), "invalidArguments"),
		(json!({"calculateTotal": "yes"}), "invalidArguments"),
	] {
		let response = query(dir.path(), args.clone()).await;
		assert_eq!(response[0], "error", "{args}");
		assert_eq!(response[1]["type"], kind, "{args}");
	}
}

#[tokio::test]
async fn an_account_queries_only_its_own_scripts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read"]);
	store(dir.path(), "bob")
		.create("private", "keep;\r\n")
		.expect("bob");
	let blocked = call(
		&app,
		&secret,
		"SieveScript/query",
		json!({"accountId": "bob"}),
	)
	.await;
	assert_eq!(blocked[1]["type"], "accountNotFound");
	let own = call(
		&app,
		&secret,
		"SieveScript/query",
		json!({"accountId": "ann", "calculateTotal": true}),
	)
	.await;
	assert_eq!(own[1]["total"], 0, "ann sees none of bob's");
}

#[tokio::test]
async fn a_key_without_the_read_scope_cannot_query_scripts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["write"]);
	let response = call(
		&app,
		&secret,
		"SieveScript/query",
		json!({"accountId": "ann"}),
	)
	.await;
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "forbidden");
}
