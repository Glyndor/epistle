//! Uploaded blobs are partitioned per account under
//! `<data_dir>/blobs/accounts/<account>/<shard>/<shard>/<id>`: a blob one
//! account uploaded is not found under another account's name, whoever asks,
//! and the reclaim sweep cleans the partitions like the legacy pool.

use super::router;
use super::tests::{TOKEN, request_raw};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Two accounts on one domain, reached with the configured token.
fn two_accounts(dir: &std::path::Path) -> crate::api::ApiState {
	let account = |name: &str| crate::config::Account {
		display_name: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![account("alice"), account("bob")],
		)
		.expect("open store"),
	);
	crate::api::ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		crate::storage::FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle())
}

async fn upload(app: &Router, account: &str, body: &[u8]) -> uuid::Uuid {
	let request = Request::builder()
		.method("POST")
		.uri(format!("/jmap/upload/{account}"))
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.header(header::CONTENT_TYPE, "text/plain")
		.body(Body::from(body.to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	assert_eq!(response.status(), StatusCode::OK, "upload status");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
	uuid::Uuid::parse_str(json["blobId"].as_str().expect("blobId")).expect("uuid")
}

/// Where the partitioned layout keeps `id` for `account`, spelled out here
/// rather than taken from the code under test.
fn partition_file(
	dir: &std::path::Path,
	account: &str,
	id: uuid::Uuid,
	suffix: &str,
) -> std::path::PathBuf {
	let bytes = id.as_bytes();
	dir.join("blobs")
		.join("accounts")
		.join(account)
		.join(format!("{:02x}", bytes[14]))
		.join(format!("{:02x}", bytes[15]))
		.join(format!("{id}{suffix}"))
}

#[tokio::test]
async fn upload_lands_in_the_uploading_accounts_partition() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(two_accounts(dir.path()));
	let id = upload(&app, "alice", b"alice bytes").await;
	for suffix in ["", ".type", ".owner"] {
		assert!(
			partition_file(dir.path(), "alice", id, suffix).is_file(),
			"blob file `{suffix}` must be in alice's partition"
		);
	}
	assert!(
		!crate::api::jmap::blob_path::read_path(dir.path(), id, "").exists(),
		"a new upload must not land in the shared legacy pool"
	);
}

#[tokio::test]
async fn a_blob_is_found_only_under_the_account_that_uploaded_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(two_accounts(dir.path()));
	let id = upload(&app, "alice", b"alice bytes").await;
	let token = Some(TOKEN.as_str());
	let own = request_raw(&app, &format!("/jmap/download/alice/{id}/f"), token).await;
	assert_eq!(own, (StatusCode::OK, b"alice bytes".to_vec()));
	let (status, body) = request_raw(&app, &format!("/jmap/download/bob/{id}/f"), token).await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"the configured token asking as bob"
	);
	let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
	assert_eq!(json["type"], "urn:ietf:params:jmap:error:notFound");
}

#[tokio::test]
async fn the_backend_does_not_find_a_blob_under_another_partition() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(two_accounts(dir.path()));
	let id = upload(&app, "alice", b"alice bytes").await;
	let backend = crate::storage::FsBackend::new(dir.path().to_path_buf());
	let alice = crate::storage::BlobAccount::new("alice").expect("alice");
	let bob = crate::storage::BlobAccount::new("bob").expect("bob");
	use crate::storage::BlobBackend;
	assert!(backend.get(&alice, id, "").await.expect("get").is_some());
	for suffix in ["", ".type", ".owner"] {
		assert_eq!(
			backend.get(&bob, id, suffix).await.expect("get"),
			None,
			"alice's `{suffix}` must not be found in bob's partition"
		);
	}
}

#[tokio::test]
async fn reclaim_sweeps_expired_blobs_out_of_the_partitions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(two_accounts(dir.path()));
	let stale = upload(&app, "alice", b"old").await;
	let fresh = upload(&app, "bob", b"new").await;
	let payload = partition_file(dir.path(), "alice", stale, "");
	assert!(
		payload.is_file(),
		"precondition: alice's upload is partitioned"
	);
	let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
	std::fs::OpenOptions::new()
		.write(true)
		.open(&payload)
		.expect("open")
		.set_modified(old)
		.expect("set mtime");

	let removed = super::jmap::reclaim_blobs(dir.path(), std::time::Duration::from_secs(24 * 3600));
	assert_eq!(removed, 1, "only the expired blob is reclaimed");
	for suffix in ["", ".type", ".owner"] {
		assert!(
			!partition_file(dir.path(), "alice", stale, suffix).exists(),
			"expired `{suffix}` must be gone from alice's partition"
		);
		assert!(
			partition_file(dir.path(), "bob", fresh, suffix).is_file(),
			"fresh `{suffix}` must stay in bob's partition"
		);
	}
}

#[tokio::test]
async fn a_legacy_blob_stays_readable_by_its_recorded_owner_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(two_accounts(dir.path()));
	let blobs = dir.path().join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	let owned = uuid::Uuid::now_v7();
	std::fs::write(blobs.join(owned.to_string()), b"legacy").expect("write");
	std::fs::write(blobs.join(format!("{owned}.owner")), b"alice").expect("write");
	let orphan = uuid::Uuid::now_v7();
	std::fs::write(blobs.join(orphan.to_string()), b"no owner").expect("write");

	let token = Some(TOKEN.as_str());
	let get = |account: &str, id: uuid::Uuid| format!("/jmap/download/{account}/{id}/f");
	assert_eq!(
		request_raw(&app, &get("alice", owned), token).await,
		(StatusCode::OK, b"legacy".to_vec())
	);
	assert_eq!(
		request_raw(&app, &get("bob", owned), token).await.0,
		StatusCode::NOT_FOUND
	);
	// Ownership was never recorded for this one: no account can claim it.
	assert_eq!(
		request_raw(&app, &get("alice", orphan), token).await.0,
		StatusCode::NOT_FOUND
	);
}
