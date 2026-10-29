//! What a `SieveScript` call costs the server must follow the bytes the
//! request brought, not the number of objects it names: a request may name
//! five hundred objects, and sixteen calls, over one blob of a mebibyte.
//! These tests count how many times a script is checked, which is the work,
//! and not how long that took.

use serde_json::{Value, json};

use super::base::TOKEN;
use super::jmap_sieve_support::{app, call_as_alice, upload};
use crate::managesieve::store::counted;

/// A script a stray brace refuses, whose first line is `marker`, so that
/// the checks made of it can be told from every other test's.
fn refused(marker: &str, n: usize) -> Vec<u8> {
	format!(
		"# {marker}{}\nkeep;\n}}\n",
		if n == 0 {
			String::new()
		} else {
			format!(" {n}")
		}
	)
	.into_bytes()
}

fn first_line(marker: &str, n: usize) -> String {
	let text = String::from_utf8(refused(marker, n)).expect("utf8");
	text.lines().next().expect("line").to_string()
}

#[tokio::test]
async fn one_blob_named_by_many_creates_is_checked_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = upload(&app, TOKEN.as_str(), "alice", &refused("cost-creates", 0)).await;
	let create: serde_json::Map<String, Value> = (0..120)
		.map(|n| {
			(
				format!("c{n}"),
				json!({"name": format!("s{n}"), "blobId": blob}),
			)
		})
		.collect();
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "create": create}),
	)
	.await;
	let refusals = response[1]["notCreated"].as_object().expect("notCreated");
	assert_eq!(refusals.len(), 120, "{response}");
	assert!(refusals.values().all(|e| e["type"] == "invalidSieve"));
	assert_eq!(
		counted::times(&first_line("cost-creates", 0)),
		1,
		"each create checked the blob again"
	);
}

#[tokio::test]
async fn one_blob_named_by_many_updates_of_scripts_that_are_not_there_is_not_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = upload(&app, TOKEN.as_str(), "alice", &refused("cost-updates", 0)).await;
	let update: serde_json::Map<String, Value> = (0..120)
		.map(|n| (format!("{n:032x}"), json!({"blobId": blob})))
		.collect();
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "update": update}),
	)
	.await;
	assert_eq!(
		response[1]["notUpdated"].as_object().map(|o| o.len()),
		Some(120),
		"{response}"
	);
	assert_eq!(counted::times(&first_line("cost-updates", 0)), 0);
}

#[tokio::test]
async fn updates_of_scripts_that_are_not_there_do_not_read_their_blobs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	// Twenty different blobs, so that no memory of a check can answer for
	// them: only refusing the id first leaves them unchecked.
	let mut update = serde_json::Map::new();
	for n in 0..20 {
		let blob = upload(&app, TOKEN.as_str(), "alice", &refused("cost-distinct", n)).await;
		update.insert(format!("{n:032x}"), json!({"blobId": blob}));
	}
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "update": update}),
	)
	.await;
	let refusals = response[1]["notUpdated"].as_object().expect("notUpdated");
	assert_eq!(refusals.len(), 20, "{response}");
	assert!(refusals.values().all(|e| e["type"] == "notFound"));
	let checked: usize = (0..20)
		.map(|n| counted::times(&first_line("cost-distinct", n)))
		.sum();
	assert_eq!(
		checked, 0,
		"a blob of a script that is not there was checked"
	);
}

/// A valid script of about `size` octets.
fn script_of(size: usize, tag: usize) -> Vec<u8> {
	format!("# {tag}\n{}keep;\n", "#".repeat(size)).into_bytes()
}

#[tokio::test]
async fn blobs_too_big_for_the_budget_are_read_only_a_few_times() {
	let dir = tempfile::tempdir().expect("tempdir");
	let budget = 100 * 1024;
	let app = super::router(super::base::test_state(dir.path(), 0).with_max_message_size(budget));
	// Nine blobs of 90 KiB: the first fits, the next four are read and put
	// aside, and the others are not read at all. A last small one is named
	// after them.
	let mut create = serde_json::Map::new();
	for n in 0..9 {
		let blob = upload(&app, TOKEN.as_str(), "alice", &script_of(90 * 1024, n)).await;
		create.insert(
			format!("c{n}"),
			json!({"name": format!("big{n}"), "blobId": blob}),
		);
	}
	let small = upload(&app, TOKEN.as_str(), "alice", b"keep;\n").await;
	create.insert(
		"last".to_string(),
		json!({"name": "small", "blobId": small}),
	);
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "create": create}),
	)
	.await;
	let created = response[1]["created"].as_object().expect("created");
	let refused = response[1]["notCreated"].as_object().expect("notCreated");
	assert!(created.contains_key("c0"), "{response}");
	assert_eq!(refused["c8"]["type"], "tooLarge", "{response}");
	assert_eq!(
		refused["last"]["type"], "tooLarge",
		"a request that has the server read four blobs for nothing gets no more: {response}"
	);
}
