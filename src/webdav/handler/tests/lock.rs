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
