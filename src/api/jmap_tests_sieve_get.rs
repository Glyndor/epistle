//! `SieveScript/get` (RFC 9661 section 2.3).

use serde_json::json;

use super::jmap_tests_sieve_support::{ann_only, app, call, call_as_alice, download, store};
use super::tests::TOKEN;

#[tokio::test]
async fn an_account_without_scripts_has_an_empty_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	let response = call_as_alice(
		&app(dir.path()),
		"SieveScript/get",
		json!({"accountId": "alice"}),
	)
	.await;
	assert_eq!(response[0], "SieveScript/get");
	assert_eq!(response[1]["accountId"], "alice");
	assert_eq!(response[1]["list"], json!([]));
	assert_eq!(response[1]["notFound"], json!([]));
	assert_eq!(response[1]["state"], "0");
}

#[tokio::test]
async fn every_script_is_listed_with_its_four_properties() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path(), "alice");
	let work = s.create("work", "keep;\r\n").expect("work");
	let draft = s.create("draft", "discard;\r\n").expect("draft");
	s.set_active(Some("work")).expect("activate");
	let response = call_as_alice(
		&app(dir.path()),
		"SieveScript/get",
		json!({"accountId": "alice"}),
	)
	.await;
	let list = response[1]["list"].as_array().expect("list");
	assert_eq!(list.len(), 2);
	let find = |name: &str| list.iter().find(|o| o["name"] == name).expect(name);
	assert_eq!(find("work")["id"], work.id);
	assert_eq!(find("work")["isActive"], true);
	assert_eq!(find("work")["blobId"], format!("sieve-{}-1", work.id));
	assert_eq!(find("draft")["id"], draft.id);
	assert_eq!(find("draft")["isActive"], false);
	assert_eq!(response[1]["state"], s.state().expect("state").to_string());
}

#[tokio::test]
async fn ids_and_properties_narrow_the_answer_and_unknown_ids_are_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path(), "alice");
	let work = s.create("work", "keep;\r\n").expect("work");
	s.create("draft", "keep;\r\n").expect("draft");
	let response = call_as_alice(
		&app(dir.path()),
		"SieveScript/get",
		json!({"accountId": "alice", "ids": [work.id, "nope"], "properties": ["name"]}),
	)
	.await;
	assert_eq!(
		response[1]["list"],
		json!([{"id": work.id, "name": "work"}])
	);
	assert_eq!(response[1]["notFound"], json!(["nope"]));
}

#[tokio::test]
async fn malformed_arguments_are_invalid_arguments() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for args in [
		json!({}),
		json!({"accountId": "alice", "ids": "x"}),
		json!({"accountId": "alice", "ids": [1]}),
		json!({"accountId": "alice", "properties": ["name", "secret"]}),
		json!({"accountId": "alice", "properties": "name"}),
	] {
		let response = call_as_alice(&app, "SieveScript/get", args.clone()).await;
		assert_eq!(response[0], "error", "{args}");
		assert_eq!(response[1]["type"], "invalidArguments", "{args}");
	}
	let response = call_as_alice(&app, "SieveScript/get", json!({"accountId": "nobody"})).await;
	assert_eq!(response[1]["type"], "accountNotFound");
}

#[tokio::test]
async fn a_change_made_through_managesieve_moves_the_state_and_shows_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let before = call_as_alice(&app, "SieveScript/get", json!({"accountId": "alice"})).await;
	store(dir.path(), "alice")
		.create("from-managesieve", "keep;\r\n")
		.expect("create");
	let after = call_as_alice(&app, "SieveScript/get", json!({"accountId": "alice"})).await;
	assert_ne!(before[1]["state"], after[1]["state"]);
	assert_eq!(after[1]["list"][0]["name"], "from-managesieve");
	let again = call_as_alice(&app, "SieveScript/get", json!({"accountId": "alice"})).await;
	assert_eq!(
		after[1]["state"], again[1]["state"],
		"reading changes nothing"
	);
}

#[tokio::test]
async fn the_blob_id_downloads_that_version_of_the_script() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let made = s.create("work", "keep;\r\n").expect("create");
	let first = format!("sieve-{}-1", made.id);
	let (status, content_type, body) = download(
		&app,
		TOKEN.as_str(),
		&format!("/jmap/download/alice/{first}/work.siv"),
	)
	.await;
	assert_eq!(status, 200);
	assert_eq!(
		content_type.as_deref(),
		Some("application/sieve; charset=utf-8")
	);
	assert_eq!(body, b"keep;\r\n");
	s.update(&made.id, None, Some("discard;\r\n"))
		.expect("rewrite");
	let (status, _, _) = download(
		&app,
		TOKEN.as_str(),
		&format!("/jmap/download/alice/{first}/work.siv"),
	)
	.await;
	assert_eq!(status, 404, "a blob does not change under its id");
	let second = format!("sieve-{}-2", made.id);
	let (_, _, body) = download(
		&app,
		TOKEN.as_str(),
		&format!("/jmap/download/alice/{second}/work.siv"),
	)
	.await;
	assert_eq!(body, b"discard;\r\n");
}

#[tokio::test]
async fn an_account_reads_only_its_own_scripts_and_blobs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read"]);
	let bobs = store(dir.path(), "bob")
		.create("private", "keep;\r\n")
		.expect("bob");
	let anns = store(dir.path(), "ann")
		.create("mine", "keep;\r\n")
		.expect("ann");
	let blocked = call(
		&app,
		&secret,
		"SieveScript/get",
		json!({"accountId": "bob"}),
	)
	.await;
	assert_eq!(blocked[1]["type"], "accountNotFound");
	let own = call(
		&app,
		&secret,
		"SieveScript/get",
		json!({"accountId": "ann"}),
	)
	.await;
	assert_eq!(own[1]["list"].as_array().map(Vec::len), Some(1));
	// Bob's script id asked for in ann's account is simply not there.
	let probe = call(
		&app,
		&secret,
		"SieveScript/get",
		json!({"accountId": "ann", "ids": [bobs.id]}),
	)
	.await;
	assert_eq!(probe[1]["list"], json!([]));
	assert_eq!(probe[1]["notFound"], json!([bobs.id]));
	// Nor can bob's blob be fetched, by bob's account or by ann's.
	for account in ["bob", "ann"] {
		let path = format!("/jmap/download/{account}/sieve-{}-1/x", bobs.id);
		let (status, _, body) = download(&app, &secret, &path).await;
		assert_eq!(status, 404, "{account}");
		assert!(
			!String::from_utf8_lossy(&body).contains("keep;"),
			"{account}"
		);
	}
	let (status, _, _) = download(
		&app,
		&secret,
		&format!("/jmap/download/ann/sieve-{}-1/x", anns.id),
	)
	.await;
	assert_eq!(status, 200);
}

#[tokio::test]
async fn a_key_without_the_read_scope_cannot_list_scripts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["write"]);
	let response = call(
		&app,
		&secret,
		"SieveScript/get",
		json!({"accountId": "ann"}),
	)
	.await;
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "forbidden");
}
