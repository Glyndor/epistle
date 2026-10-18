//! What a `SieveScript` call costs the server must follow the bytes the
//! request brought, not the number of objects it names: a request may name
//! five hundred objects, and sixteen calls, over one blob of a mebibyte.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{app, call_as_alice, upload};
use super::tests::TOKEN;
use crate::managesieve::store::MAX_SCRIPT_BYTES;

/// A script of nearly the largest size that is valid up to its last octet,
/// where a stray brace refuses it: it is read in full to be refused.
fn refused_at_the_end() -> Vec<u8> {
	let mut script = "keep;\n".repeat((MAX_SCRIPT_BYTES - 16) / 6).into_bytes();
	script.extend_from_slice(b"}\n");
	script
}

#[tokio::test]
async fn one_blob_named_by_many_creates_is_checked_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = upload(&app, TOKEN.as_str(), "alice", &refused_at_the_end()).await;
	let create: serde_json::Map<String, Value> = (0..120)
		.map(|n| {
			(
				format!("c{n}"),
				json!({"name": format!("s{n}"), "blobId": blob}),
			)
		})
		.collect();
	let started = Instant::now();
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "create": create}),
	)
	.await;
	let took = started.elapsed();
	let refused = response[1]["notCreated"].as_object().expect("notCreated");
	assert_eq!(refused.len(), 120, "{response}");
	assert!(refused.values().all(|e| e["type"] == "invalidSieve"));
	assert!(
		took < Duration::from_secs(4),
		"120 creates over one 1 MiB blob took {took:?}: each was read again"
	);
}

#[tokio::test]
async fn one_blob_named_by_many_updates_of_scripts_that_are_not_there_is_not_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let blob = upload(&app, TOKEN.as_str(), "alice", &refused_at_the_end()).await;
	let update: serde_json::Map<String, Value> = (0..120)
		.map(|n| (format!("{n:032x}"), json!({"blobId": blob})))
		.collect();
	let started = Instant::now();
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "update": update}),
	)
	.await;
	let took = started.elapsed();
	assert_eq!(
		response[1]["notUpdated"].as_object().map(|o| o.len()),
		Some(120),
		"{response}"
	);
	assert!(took < Duration::from_secs(4), "{took:?}");
}

/// A valid script of about `size` octets.
fn script_of(size: usize, tag: usize) -> Vec<u8> {
	format!("# {tag}\n{}keep;\n", "#".repeat(size)).into_bytes()
}

#[tokio::test]
async fn blobs_too_big_for_the_budget_are_read_only_a_few_times() {
	let dir = tempfile::tempdir().expect("tempdir");
	let budget = 100 * 1024;
	let app = super::router(super::tests::test_state(dir.path(), 0).with_max_message_size(budget));
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

#[tokio::test]
async fn updates_of_scripts_that_are_not_there_do_not_read_their_blobs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	// Twenty different blobs, so that no memory of a check can answer for
	// them: only refusing the id first leaves them unread.
	let mut update = serde_json::Map::new();
	for n in 0..20 {
		let mut script = refused_at_the_end();
		script.extend_from_slice(format!("# {n}\n").as_bytes());
		let blob = upload(&app, TOKEN.as_str(), "alice", &script).await;
		update.insert(format!("{n:032x}"), json!({"blobId": blob}));
	}
	let started = Instant::now();
	let response = call_as_alice(
		&app,
		"SieveScript/set",
		json!({"accountId": "alice", "update": update}),
	)
	.await;
	let took = started.elapsed();
	let refused = response[1]["notUpdated"].as_object().expect("notUpdated");
	assert_eq!(refused.len(), 20, "{response}");
	assert!(refused.values().all(|e| e["type"] == "notFound"));
	assert!(took < Duration::from_secs(1), "{took:?}");
}
