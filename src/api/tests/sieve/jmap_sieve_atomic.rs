//! A `/set` is one step: `ifInState` is checked where the change is made,
//! the active script changes without a moment of no filter, and a creation
//! can be named in the same call.

use serde_json::{Value, json};

use super::base::TOKEN;
use super::jmap_sieve_support::{app, call_as_alice, store, upload};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn if_in_state_lets_one_of_four_simultaneous_calls_through() {
	for round in 0..10 {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		let state = call_as_alice(&app, "SieveScript/get", json!({"accountId": "alice"})).await[1]
			["state"]
			.clone();
		let mut blobs = Vec::new();
		for n in 0..4 {
			blobs.push(blob(&app, format!("# {n}\r\nkeep;\r\n").as_bytes()).await);
		}
		let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
		let tasks: Vec<_> = blobs
			.into_iter()
			.enumerate()
			.map(|(n, blob)| {
				let (app, state, barrier) = (app.clone(), state.clone(), barrier.clone());
				tokio::spawn(async move {
					barrier.wait().await;
					set(
						&app,
						json!({"ifInState": state, "create": {"a": {"name": format!("s{n}"), "blobId": blob}}}),
					)
					.await
				})
			})
			.collect();
		let mut won = 0;
		let mut lost = 0;
		for task in tasks {
			let response = task.await.expect("task");
			if response[0] == "SieveScript/set" {
				won += 1;
			} else {
				assert_eq!(response[1]["type"], "stateMismatch");
				lost += 1;
			}
		}
		assert_eq!((won, lost), (1, 3), "round {round}");
		assert_eq!(
			store(dir.path(), "alice").list().expect("list").len(),
			1,
			"round {round}"
		);
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_filter_is_never_missing_while_the_active_script_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let a = s.create("a", "keep;\r\n").expect("a");
	let b = s.create("b", "discard;\r\n").expect("b");
	s.set_active(Some("a")).expect("activate");
	let live = dir.path().join("accounts/alice/filter.sieve");
	let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let watcher = {
		let (stop, live) = (stop.clone(), live.clone());
		std::thread::spawn(move || {
			let mut missing = 0u32;
			while !stop.load(std::sync::atomic::Ordering::Relaxed) {
				if !live.exists() {
					missing += 1;
				}
			}
			missing
		})
	};
	for round in 0..120 {
		let target = if round % 2 == 0 { &b.id } else { &a.id };
		set(
			&app,
			json!({"onSuccessDeactivateScript": true, "onSuccessActivateScript": target}),
		)
		.await;
	}
	stop.store(true, std::sync::atomic::Ordering::Relaxed);
	let missing = watcher.join().expect("watcher");
	assert_eq!(
		missing, 0,
		"the filter was missing {missing} times while it was switched"
	);
}

#[tokio::test]
async fn a_creation_can_be_destroyed_in_the_same_call() {
	// `#cid` names a creation of the same call in `destroy` and in
	// `onSuccessActivateScript`. (In `update` the key would be read as a
	// result reference by the dispatcher, RFC 8620 section 3.7.)
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let first = blob(&app, b"keep;\r\n").await;
	let response = set(
		&app,
		json!({
			"create": {"a": {"name": "first", "blobId": first}, "b": {"name": "second", "blobId": first}},
			"destroy": ["#b"],
		}),
	)
	.await;
	let b = response[1]["created"]["b"]["id"]
		.as_str()
		.unwrap_or_else(|| panic!("{response}"))
		.to_string();
	assert_eq!(response[1]["destroyed"], json!([b]));
	let s = store(dir.path(), "alice");
	assert!(s.get("first").is_ok());
	assert!(s.get("second").is_err());
	// A reference to nothing is not found.
	let missing = set(&app, json!({"destroy": ["#nope"]})).await;
	assert_eq!(
		missing[1]["notDestroyed"]["#nope"],
		json!({"type": "notFound"})
	);
}
