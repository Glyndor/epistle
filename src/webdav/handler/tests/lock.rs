//! `DELETE` and `MOVE` change the tree without a quota check, so they must
//! hold the account's write lock while they do, or a `COPY` that measured the
//! tree before could copy something else. The handlers are called directly:
//! going through the router would spend longer on the password hash than the
//! wait that shows the lock is taken.

use std::time::Duration;

use axum::http::HeaderMap;

use super::{copy_move, delete};
use crate::test_fixtures as fixtures;
use crate::webdav::quota::Quota;

fn quota_for(dir: &std::path::Path) -> Quota {
	quota_with(dir, Some(1_000_000))
}

fn quota_with(dir: &std::path::Path, quota_bytes: Option<u64>) -> Quota {
	let account = crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some(crate::smtp::auth::hash_password(fixtures::password()).expect("hash")),
		catch_all: Vec::new(),
		quota_bytes,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = crate::directory_store::AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![account],
	)
	.expect("store");
	let state = crate::webdav::WebDavState {
		directory: store.handle(),
		data_dir: dir.to_path_buf(),
		trusted_proxies: Vec::new(),
		quota_default: 0,
		crypto: crate::storage::MessageCrypto::disabled(),
	};
	Quota::new(&state, "alice", &dir.join("accounts/alice/dav"))
}

#[tokio::test]
async fn delete_waits_for_the_accounts_lock() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav");
	std::fs::create_dir_all(&root).expect("dav");
	std::fs::write(root.join("a.bin"), b"x").expect("file");
	let quota = quota_for(dir.path());
	let held = quota.exclusive().await;
	let pending = tokio::time::timeout(
		Duration::from_millis(200),
		delete(&root.join("a.bin"), &quota),
	)
	.await;
	assert!(
		pending.is_err(),
		"DELETE waits while another write holds the lock"
	);
	assert!(root.join("a.bin").exists());
	drop(held);
	assert_eq!(delete(&root.join("a.bin"), &quota).await.status(), 204);
}

#[tokio::test]
async fn move_waits_for_the_accounts_lock() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav");
	std::fs::create_dir_all(&root).expect("dav");
	std::fs::write(root.join("a.bin"), b"x").expect("file");
	let quota = quota_for(dir.path());
	let mut headers = HeaderMap::new();
	headers.insert(
		"Destination",
		"http://localhost/b.bin".parse().expect("header"),
	);
	let held = quota.exclusive().await;
	let pending = tokio::time::timeout(
		Duration::from_millis(200),
		copy_move(&root, &root.join("a.bin"), &headers, true, &quota),
	)
	.await;
	assert!(
		pending.is_err(),
		"MOVE waits while another write holds the lock"
	);
	assert!(root.join("a.bin").exists() && !root.join("b.bin").exists());
	drop(held);
	let moved = copy_move(&root, &root.join("a.bin"), &headers, true, &quota).await;
	assert_eq!(moved.status(), 201);
}

fn headers_to(destination: &str) -> HeaderMap {
	let mut headers = HeaderMap::new();
	headers.insert("Destination", destination.parse().expect("header"));
	headers
}

/// Two moves that are each within the depth bound alone but not together: the
/// second must see what the first made, so the bound is checked with the
/// account's lock held.
async fn two_moves_cannot_add_up_past_the_depth_bound(quota_bytes: Option<u64>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav");
	// `k` holds 13 levels below it, `s` is empty, `t` is 9 deep.
	std::fs::create_dir_all(root.join("k/c/c/c/c/c/c/c/c/c/c/c/c/c")).expect("k");
	std::fs::create_dir_all(root.join("s")).expect("s");
	std::fs::create_dir_all(root.join("t/d/d/d/d/d/d/d/d")).expect("t");
	let quota = std::sync::Arc::new(quota_with(dir.path(), quota_bytes));
	// Another write holds the lock while both moves are issued, so both are
	// waiting for it, the first one first, when it is released.
	let held = quota.exclusive().await;
	let issue = |from: &'static str, to: &'static str| {
		let (quota, root) = (std::sync::Arc::clone(&quota), root.clone());
		tokio::spawn(async move {
			let headers = headers_to(to);
			copy_move(&root, &root.join(from), &headers, true, &quota).await
		})
	};
	let first = issue("k", "http://localhost/s/k");
	tokio::time::sleep(Duration::from_millis(100)).await;
	let second = issue("s", "http://localhost/t/d/d/d/d/d/d/d/d/s");
	tokio::time::sleep(Duration::from_millis(100)).await;
	drop(held);
	let (a, b) = (first.await.expect("first"), second.await.expect("second"));
	assert_eq!(a.status(), 201);
	assert_eq!(b.status(), 403, "the second sees the first's depth");
	assert!(root.join("s/k").exists() && !root.join("t/d/d/d/d/d/d/d/d/s").exists());
}

#[tokio::test]
async fn two_moves_stay_within_the_depth_bound_with_a_quota() {
	two_moves_cannot_add_up_past_the_depth_bound(Some(1_000_000)).await;
}

#[tokio::test]
async fn two_moves_stay_within_the_depth_bound_without_a_quota() {
	two_moves_cannot_add_up_past_the_depth_bound(Some(0)).await;
}

/// Issues `copy_move` while another write holds the lock, lets the tree
/// change, then releases the lock: the request must judge what is there now,
/// not what was there when it arrived.
async fn issue_then_change<F: FnOnce(&std::path::Path)>(
	remove: bool,
	overwrite: Option<&'static str>,
	change: F,
) -> (
	axum::response::Response,
	std::path::PathBuf,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav");
	std::fs::create_dir_all(&root).expect("dav");
	std::fs::write(root.join("a.bin"), b"source").expect("file");
	let quota = std::sync::Arc::new(quota_for(dir.path()));
	let held = quota.exclusive().await;
	let mut headers = headers_to("http://localhost/b.bin");
	if let Some(value) = overwrite {
		headers.insert("Overwrite", value.parse().expect("header"));
	}
	let pending = {
		let (quota, root) = (std::sync::Arc::clone(&quota), root.clone());
		tokio::spawn(async move {
			copy_move(&root, &root.join("a.bin"), &headers, remove, &quota).await
		})
	};
	tokio::time::sleep(Duration::from_millis(150)).await;
	change(&root);
	drop(held);
	(pending.await.expect("request"), root, dir)
}

#[tokio::test]
async fn copy_without_overwrite_sees_a_destination_created_while_it_waited() {
	let (response, root, _dir) = issue_then_change(false, Some("F"), |root| {
		std::fs::write(root.join("b.bin"), b"theirs").expect("created");
	})
	.await;
	assert_eq!(response.status(), 412);
	assert_eq!(std::fs::read(root.join("b.bin")).expect("kept"), b"theirs");
}

#[tokio::test]
async fn move_without_overwrite_sees_a_destination_created_while_it_waited() {
	let (response, root, _dir) = issue_then_change(true, Some("F"), |root| {
		std::fs::write(root.join("b.bin"), b"theirs").expect("created");
	})
	.await;
	assert_eq!(response.status(), 412);
	assert_eq!(std::fs::read(root.join("b.bin")).expect("kept"), b"theirs");
	assert!(root.join("a.bin").exists(), "the source stays");
}

#[tokio::test]
async fn copy_over_a_destination_created_while_it_waited_replaces_it() {
	let (response, root, _dir) = issue_then_change(false, None, |root| {
		std::fs::write(root.join("b.bin"), b"theirs").expect("created");
	})
	.await;
	assert_eq!(response.status(), 204, "it replaced something");
	assert_eq!(std::fs::read(root.join("b.bin")).expect("copy"), b"source");
}

#[tokio::test]
async fn move_whose_source_vanished_while_it_waited_is_not_found() {
	let (response, root, _dir) = issue_then_change(true, None, |root| {
		std::fs::remove_file(root.join("a.bin")).expect("removed");
	})
	.await;
	assert_eq!(response.status(), 404);
	assert!(!root.join("b.bin").exists());
}

#[tokio::test]
async fn move_whose_source_became_a_link_while_it_waited_is_forbidden() {
	let (response, root, _dir) = issue_then_change(true, None, |root| {
		std::fs::remove_file(root.join("a.bin")).expect("removed");
		std::os::unix::fs::symlink("/etc/hostname", root.join("a.bin")).expect("link");
	})
	.await;
	assert_eq!(response.status(), 403);
	assert!(!root.join("b.bin").exists());
}
