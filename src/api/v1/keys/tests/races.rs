//! Writes that overlap: a revoked key stays revoked.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;
use crate::api::api_keys::ApiKeyStore;
use crate::directory_store::{AccountStore, FileWatcher};
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The account store another process opens on the same data directory.
fn sibling(world: &World) -> Arc<AccountStore> {
	Arc::new(
		AccountStore::open(
			world.state.data_dir(),
			vec!["a.example".to_string(), "b.example".to_string()],
			HashMap::new(),
			Vec::new(),
		)
		.expect("sibling store"),
	)
}

fn file(world: &World, name: &str) -> std::path::PathBuf {
	world.state.data_dir().join(name)
}

fn accepted(world: &World, label: &str) -> bool {
	let keys = world.state.api_keys().snapshot();
	keys.iter().any(|key| key.label == label)
}

/// Make the next reload of the running set stop between reading the file and
/// swapping the keys. Answers the signal that it got there and the release.
fn hold_next_reload(
	world: &World,
) -> (
	tokio::sync::oneshot::Receiver<()>,
	std::sync::mpsc::Sender<()>,
) {
	let (there, reached) = tokio::sync::oneshot::channel();
	let (release, released) = std::sync::mpsc::channel::<()>();
	world.state.api_keys().pause_next_reload(move || {
		there.send(()).ok();
		released.recv_timeout(LIMIT).ok();
	});
	(reached, release)
}

async fn send(
	world: &World,
	method: &'static str,
	path: &'static str,
	bearer: &'static str,
	body: Option<serde_json::Value>,
) -> tokio::task::JoinHandle<(StatusCode, serde_json::Value)> {
	let state = world.state.clone();
	tokio::spawn(async move {
		let (status, _, body) = call(&state, method, path, bearer, body).await;
		(status, body)
	})
}

/// One write has read the file and not yet put it in memory when another
/// revokes a key: the revoked key stays out of the running set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_key_stays_revoked_when_two_writes_overlap() {
	let world = world();
	let mut watcher = FileWatcher::new(world.state.data_dir().to_path_buf(), sibling(&world))
		.with_api_keys(Arc::clone(world.state.api_keys()) as _);
	let lock = lock_path(&file(&world, "api_keys.toml"));
	let (there, release) = hold_next_reload(&world);
	let child = json!({"label": "child", "scopes": ["read"]});
	let first = send(&world, "POST", "/api/v1/keys", MAKER, Some(child)).await;
	tokio::time::timeout(LIMIT, there)
		.await
		.expect("in time")
		.expect("the first write reloads");
	// A reload that holds no lock lets the second write, and a poll of the
	// watcher, finish while the first one still has the old text. One that
	// holds it makes them wait.
	let free = FileLock::try_acquire(&lock).expect("probe").is_some();
	let second = send(&world, "DELETE", "/api/v1/keys/of-a", MAKER, None).await;
	let second = if free {
		let answered = second.await.expect("revoked");
		watcher.poll();
		release.send(()).expect("release");
		answered
	} else {
		release.send(()).expect("release");
		second.await.expect("revoked")
	};
	let first = first.await.expect("created");
	assert_eq!(first.0, StatusCode::CREATED, "{}", first.1);
	assert_eq!(second.0, StatusCode::OK, "{}", second.1);
	// The watcher gets its turn too: what it saw last must be what runs.
	watcher.poll();
	assert!(!accepted(&world, "of-a"), "a revoked key is accepted again");
	assert!(accepted(&world, "child"), "the new key is not accepted");
}

/// The watcher has read the file and not yet put it in memory when a key is
/// revoked over the API: the revoked key stays out of the running set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_poll_that_read_before_a_revocation_does_not_bring_the_key_back() {
	let world = world();
	let mut watcher = FileWatcher::new(world.state.data_dir().to_path_buf(), sibling(&world))
		.with_api_keys(Arc::clone(world.state.api_keys()) as _);
	// Another process writes the file, so the poll has something to read.
	ApiKeyStore::open(world.state.data_dir())
		.expect("open")
		.set_auto_submitted("of-b", true)
		.expect("write");
	let lock = lock_path(&file(&world, "api_keys.toml"));
	let (there, release) = hold_next_reload(&world);
	let poll = tokio::task::spawn_blocking(move || watcher.poll());
	tokio::time::timeout(LIMIT, there)
		.await
		.expect("in time")
		.expect("the poll reloads");
	let free = FileLock::try_acquire(&lock).expect("probe").is_some();
	let revoke = send(&world, "DELETE", "/api/v1/keys/of-a", MAKER, None).await;
	let revoked = if free {
		let answered = revoke.await.expect("revoked");
		release.send(()).expect("release");
		answered
	} else {
		release.send(()).expect("release");
		revoke.await.expect("revoked")
	};
	poll.await.expect("polled");
	assert_eq!(revoked.0, StatusCode::OK, "{}", revoked.1);
	assert!(!accepted(&world, "of-a"), "a revoked key is accepted again");
}
