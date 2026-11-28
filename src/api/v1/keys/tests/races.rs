//! Writes that overlap: a revoked key stays revoked, and a key bound to an
//! account is written only while that account is as it was asked about.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;
use crate::api::api_keys::ApiKeyStore;
use crate::directory_store::{AccountStore, DynamicAccount, FileWatcher, QueuePolicy};
use crate::storage::lock::{FileLock, reached};
use crate::storage::locked::{before_write, lock_path};

const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

fn carol(address: &str) -> DynamicAccount {
	DynamicAccount {
		name: "carol".to_string(),
		addresses: vec![address.to_string()],
		password_hash: crate::smtp::auth::tests::base::hash("a password"),
		..DynamicAccount::default()
	}
}

/// The world with the dynamic account `carol` in `a.example`.
fn with_carol() -> World {
	let world = world();
	world
		.state
		.store()
		.add(carol("carol@a.example"))
		.expect("add carol");
	world
}

/// Remove `carol` on a thread of its own, as another request would.
fn remove_carol(world: &World) {
	std::thread::scope(|scope| {
		let removal = scope.spawn(|| {
			tokio::runtime::Builder::new_current_thread()
				.build()
				.expect("runtime")
				.block_on(crate::directory_store::remove_account(
					world.state.store(),
					world.state.spool(),
					world.state.data_dir(),
					"carol",
					QueuePolicy::Drain,
					None,
				))
				.expect("remove carol");
		});
		removal.join().expect("removed");
	});
}

fn bound_to_carol() -> serde_json::Value {
	json!({"label": "child", "scopes": ["read"], "account": "carol"})
}

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

/// No other writer can move the account between the moment the key is checked
/// against it and the moment the key is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_does_not_move_between_the_check_and_the_write_of_its_key() {
	let world = with_carol();
	let accounts = lock_path(&file(&world, "accounts.toml"));
	let moved = Arc::new(AtomicBool::new(false));
	let (other, seen) = (sibling(&world), Arc::clone(&moved));
	before_write::run_once(&file(&world, "api_keys.toml"), move || {
		// Whoever can take the lock of the accounts here can move one.
		if FileLock::try_acquire(&accounts).expect("probe").is_some() {
			std::thread::spawn(move || {
				other
					.replace_account("carol", carol("carol@b.example"), None)
					.expect("move carol");
			})
			.join()
			.expect("moved");
			seen.store(true, Ordering::SeqCst);
		}
	});
	let body = Some(bound_to_carol());
	let (status, _, body) = call(&world.state, "POST", "/api/v1/keys", MAKER_A, body).await;
	assert!(
		!moved.load(Ordering::SeqCst),
		"the account moved while its key was being written: {status} {body}"
	);
	assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// An account another process moved is read as the file has it, also before
/// the watcher has brought the running directory up to date.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_moved_by_another_process_is_not_bound() {
	let world = with_carol();
	sibling(&world)
		.replace_account("carol", carol("carol@b.example"), None)
		.expect("move carol");
	let body = Some(bound_to_carol());
	let (status, _, body) = call(&world.state, "POST", "/api/v1/keys", MAKER_A, body).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(!labels(&world).contains(&"child".to_string()));
}

/// The same for an account another process removed, whoever asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_removed_by_another_process_is_not_bound() {
	for bearer in [token(), MAKER] {
		let world = with_carol();
		sibling(&world).remove("carol").expect("remove carol");
		let body = Some(bound_to_carol());
		let (status, _, body) = call(&world.state, "POST", "/api/v1/keys", bearer, body).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
		assert!(body.to_string().contains("no such account"), "{body}");
		assert!(!labels(&world).contains(&"child".to_string()));
	}
}

/// A removal that runs while a key for the account waits to be written leaves
/// no key behind, whichever of the two goes first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_does_not_outlive_the_account_removed_while_it_was_made() {
	let world = with_carol();
	let keys = lock_path(&file(&world, "api_keys.toml"));
	let accounts = lock_path(&file(&world, "accounts.toml"));
	let held = FileLock::acquire(&keys).expect("lock");
	let waiting = reached::watch(&keys);
	let body = Some(bound_to_carol());
	let request = send(&world, "POST", "/api/v1/keys", token(), body).await;
	tokio::time::timeout(LIMIT, waiting.acquire())
		.await
		.expect("the write asks for the lock")
		.expect("open")
		.forget();
	if FileLock::try_acquire(&accounts).expect("probe").is_some() {
		remove_carol(&world);
		drop(held);
		request.await.expect("answered");
	} else {
		drop(held);
		request.await.expect("answered");
		remove_carol(&world);
	}
	let left = labels(&world);
	assert!(
		!left.contains(&"child".to_string()),
		"a key survived: {left:?}"
	);
}
