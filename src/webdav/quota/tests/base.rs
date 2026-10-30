use axum::Router;
use axum::http::StatusCode;

use super::{Change, MIN_ENTRY_BYTES, Quota, tree_cost};
use crate::test_fixtures as fixtures;
use crate::webdav::test_support::send_as_alice;

fn app_with_quota(dir: &std::path::Path, quota_bytes: Option<u64>) -> Router {
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
	crate::webdav::router(store.handle(), dir.to_path_buf())
}

async fn put(app: &Router, path: &str, size: usize) -> StatusCode {
	send_as_alice(app, "PUT", path, &[], &vec![b'x'; size])
		.await
		.0
}

fn dav_file(dir: &std::path::Path, relative: &str) -> std::path::PathBuf {
	dir.join("accounts/alice/dav").join(relative)
}

fn state_for(dir: &std::path::Path, quota_bytes: Option<u64>) -> crate::webdav::WebDavState {
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
	crate::webdav::WebDavState {
		directory: store.handle(),
		data_dir: dir.to_path_buf(),
		trusted_proxies: Vec::new(),
		quota_default: 0,
		crypto: crate::storage::MessageCrypto::disabled(),
	}
}

fn quota_for(dir: &std::path::Path, limit: u64) -> Quota {
	let state = state_for(dir, Some(limit));
	Quota::new(&state, "alice", &dir.join("accounts/alice/dav"))
}

#[tokio::test]
async fn a_put_over_the_quota_is_refused_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(10_000));
	assert_eq!(put(&app, "/a.bin", 6000).await, StatusCode::CREATED);
	let (status, body) = send_as_alice(&app, "PUT", "/b.bin", &[], &[b'x'; 6000]).await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
	assert!(body.contains("sufficient-disk-space"), "{body}");
	assert!(!dav_file(dir.path(), "b.bin").exists());
}

#[tokio::test]
async fn replacing_a_file_counts_only_the_growth() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(10_000));
	assert_eq!(put(&app, "/a.bin", 6000).await, StatusCode::CREATED);
	assert_eq!(put(&app, "/a.bin", 9500).await, StatusCode::NO_CONTENT);
	assert_eq!(
		put(&app, "/a.bin", 10_001).await,
		StatusCode::INSUFFICIENT_STORAGE
	);
	assert_eq!(tree_cost(&dav_file(dir.path(), "a.bin"), true), 9500);
}

#[tokio::test]
async fn a_write_that_shrinks_a_file_is_allowed_while_over_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav");
	std::fs::create_dir_all(&root).expect("dav");
	std::fs::write(root.join("a.bin"), vec![b'x'; 9000]).expect("file");
	// Mail arrived and took the account over its quota of 10000.
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(inbox.join("0001.eml"), vec![b'm'; 6000]).expect("mail");
	let quota = quota_for(dir.path(), 10_000);
	let grows = quota
		.admit(Change {
			bytes: 6000,
			..Change::default()
		})
		.await;
	assert!(grows.is_err());
	let shrinks = quota
		.admit(Change {
			bytes: 5000,
			replaces: Some(root.join("a.bin")),
			..Change::default()
		})
		.await;
	assert!(shrinks.is_ok());
}

#[tokio::test]
async fn stored_mail_counts_against_the_same_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(inbox.join("0001.eml"), vec![b'm'; 5000]).expect("mail");
	let app = app_with_quota(dir.path(), Some(10_000));
	assert_eq!(
		put(&app, "/a.bin", 6000).await,
		StatusCode::INSUFFICIENT_STORAGE
	);
	assert_eq!(put(&app, "/a.bin", 4500).await, StatusCode::CREATED);
}

#[tokio::test]
async fn an_account_with_no_limit_is_not_measured() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(0));
	assert_eq!(put(&app, "/a.bin", 40_000).await, StatusCode::CREATED);
}

#[tokio::test]
async fn collections_and_empty_files_cost_a_block_each() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(10_000));
	let mkcol = |path: &'static str| {
		let app = app.clone();
		async move { send_as_alice(&app, "MKCOL", path, &[], b"").await.0 }
	};
	assert_eq!(mkcol("/a/").await, StatusCode::CREATED);
	assert_eq!(mkcol("/b/").await, StatusCode::CREATED);
	assert_eq!(mkcol("/c/").await, StatusCode::INSUFFICIENT_STORAGE);
	assert!(!dav_file(dir.path(), "c").exists());
	assert_eq!(
		put(&app, "/empty", 0).await,
		StatusCode::INSUFFICIENT_STORAGE
	);
	assert_eq!(MIN_ENTRY_BYTES, 4096);
}

#[tokio::test]
async fn copying_a_file_or_a_collection_counts_its_real_size() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(17_000));
	assert_eq!(put(&app, "/a.bin", 8000).await, StatusCode::CREATED);
	assert_eq!(put(&app, "/c.bin", 6000).await, StatusCode::CREATED);
	let copy = |from: &'static str, to: &'static str| {
		let app = app.clone();
		async move {
			let destination = format!("http://localhost{to}");
			send_as_alice(&app, "COPY", from, &[("Destination", &destination)], b"")
				.await
				.0
		}
	};
	assert_eq!(
		copy("/a.bin", "/b.bin").await,
		StatusCode::INSUFFICIENT_STORAGE
	);
	assert!(!dav_file(dir.path(), "b.bin").exists());
	// A copy onto an existing file frees that file's bytes before it adds
	// its own: 14000 stored, 6000 freed, 8000 added.
	assert_eq!(copy("/a.bin", "/c.bin").await, StatusCode::NO_CONTENT);

	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(20_000));
	assert_eq!(
		send_as_alice(&app, "MKCOL", "/folder/", &[], b"").await.0,
		StatusCode::CREATED
	);
	assert_eq!(
		put(&app, "/folder/one.bin", 5000).await,
		StatusCode::CREATED
	);
	assert_eq!(
		put(&app, "/folder/two.bin", 5000).await,
		StatusCode::CREATED
	);
	let (status, _) = send_as_alice(
		&app,
		"COPY",
		"/folder/",
		&[("Destination", "http://localhost/copy/")],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
	assert!(!dav_file(dir.path(), "copy").exists());
}

#[tokio::test]
async fn moving_never_grows_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(10_000));
	assert_eq!(put(&app, "/a.bin", 9000).await, StatusCode::CREATED);
	let (status, _) = send_as_alice(
		&app,
		"MOVE",
		"/a.bin",
		&[("Destination", "http://localhost/b.bin")],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn concurrent_writes_cannot_each_pass_the_same_free_space() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(10_000));
	let (a, b, c, d, e, f) = tokio::join!(
		put(&app, "/a.bin", 4096),
		put(&app, "/b.bin", 4096),
		put(&app, "/c.bin", 4096),
		put(&app, "/d.bin", 4096),
		put(&app, "/e.bin", 4096),
		put(&app, "/f.bin", 4096),
	);
	let created = [a, b, c, d, e, f]
		.iter()
		.filter(|status| **status == StatusCode::CREATED)
		.count();
	assert_eq!(created, 2);
	assert!(tree_cost(&dir.path().join("accounts/alice/dav"), false) <= 10_000);
}

#[tokio::test]
async fn a_write_holds_the_accounts_quota_lock_until_it_is_done() {
	use std::time::Duration;
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota_for(dir.path(), 100_000);
	let change = || Change {
		bytes: 10,
		..Change::default()
	};
	let first = quota.admit(change()).await.expect("fits");
	let waiting = tokio::time::timeout(Duration::from_millis(200), quota.admit(change())).await;
	assert!(waiting.is_err(), "a second write waits for the first");
	drop(first);
	assert!(quota.admit(change()).await.is_ok());
}

#[tokio::test]
async fn delete_and_move_take_the_same_lock() {
	use std::time::Duration;
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota_for(dir.path(), 100_000);
	let held = quota.exclusive().await;
	let waiting =
		tokio::time::timeout(Duration::from_millis(200), quota.admit(Change::default())).await;
	assert!(waiting.is_err(), "a write waits for a delete or a move");
	drop(held);
}

#[tokio::test]
async fn the_tree_is_walked_once_not_for_every_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota_for(dir.path(), 1_000_000);
	for n in 0..5 {
		let target = dir.path().join(format!("accounts/alice/dav/{n}.bin"));
		std::fs::create_dir_all(target.parent().expect("parent")).expect("dav");
		let reservation = quota
			.admit(Change {
				bytes: 5000,
				..Change::default()
			})
			.await
			.expect("fits");
		std::fs::write(&target, vec![b'x'; 5000]).expect("write");
		drop(reservation);
	}
	assert_eq!(quota.walks(), 1);
	// A removal makes the kept total stale: the next write walks again.
	std::fs::remove_file(dir.path().join("accounts/alice/dav/0.bin")).expect("remove");
	drop(quota.exclusive().await);
	drop(quota.admit(Change::default()).await.expect("fits"));
	assert_eq!(quota.walks(), 2);
}

#[tokio::test]
async fn a_calendar_is_charged_for_its_change_log_when_it_is_made() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(100_000));
	let (status, _) = send_as_alice(
		&app,
		"MKCOL",
		"/cal/",
		&[],
		crate::webdav::test_support::MKCOL_CALENDAR,
	)
	.await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with_quota(dir.path(), Some(1_000_000));
	let (status, _) = send_as_alice(
		&app,
		"MKCOL",
		"/cal/",
		&[],
		crate::webdav::test_support::MKCOL_CALENDAR,
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	// A log that grew is measured at the reserve, not at its size.
	let log = dav_file(dir.path(), "cal/.changelog");
	std::fs::write(&log, vec![b'x'; 60_000]).expect("log");
	assert_eq!(tree_cost(&log, true), super::LOG_RESERVE);
}

#[tokio::test]
async fn one_request_measures_the_mail_when_the_measure_expires() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota_for(dir.path(), 1_000_000);
	let one = || async { quota.admit(Change::default()).await.is_ok() };
	let (a, b, c, d) = tokio::join!(one(), one(), one(), one());
	assert!(a && b && c && d);
	assert_eq!(quota.mail_walks(), 1);
}

#[tokio::test]
async fn writes_of_an_account_with_no_quota_still_go_one_at_a_time() {
	use std::time::Duration;
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_for(dir.path(), Some(0));
	let quota = Quota::new(&state, "alice", &dir.path().join("accounts/alice/dav"));
	let first = quota.admit(Change::default()).await.expect("no limit");
	let waiting =
		tokio::time::timeout(Duration::from_millis(200), quota.admit(Change::default())).await;
	assert!(waiting.is_err(), "a second write waits for the first");
	drop(first);
	assert!(quota.admit(Change::default()).await.is_ok());
	let held = quota.exclusive().await;
	let waiting =
		tokio::time::timeout(Duration::from_millis(200), quota.admit(Change::default())).await;
	assert!(waiting.is_err(), "a delete or move holds the lock too");
	drop(held);
}
