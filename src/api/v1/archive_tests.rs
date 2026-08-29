use axum::http::StatusCode;

use crate::api::state::ApiState;
use crate::api::tests::{TOKEN, request};
use crate::imap::archive;
use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::storage::MessageCrypto;

async fn archive_test_state() -> (tempfile::TempDir, ApiState) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("open spool");
	let accounts = vec![crate::config::Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle());
	(dir, state)
}

/// Append one message and expunge with `retention=30` so the resulting
/// archive has a single entry to read back from the API.
async fn seed_one_archived_message(dir: &tempfile::TempDir) -> uuid::Uuid {
	let id = mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: hi\r\n\r\nbody\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");
	id
}

#[tokio::test]
async fn archive_list_returns_seeded_entries() {
	let (dir, state) = archive_test_state().await;
	let id = seed_one_archived_message(&dir).await;

	let app = super::super::super::router(state);
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/archive",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0]["id"].as_str(), Some(id.to_string().as_str()));
	assert_eq!(entries[0]["mailbox"], "INBOX");
	assert_eq!(entries[0]["deleted_at"], 1_000);
}

#[tokio::test]
async fn archive_list_is_empty_when_no_retention_writes_have_happened() {
	let (_dir, state) = archive_test_state().await;
	// No expunges ever recorded: the archive directory does not exist, the
	// listing is the empty array, not a 404 (the route is always present,
	// it is retention that toggles whether anything lives in there).
	let app = super::super::super::router(state);
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/archive",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(body["entries"].as_array().expect("entries").is_empty());
}

#[tokio::test]
async fn archive_restore_round_trips_message_to_mailbox() {
	let (dir, state) = archive_test_state().await;
	let id = seed_one_archived_message(&dir).await;

	let app = super::super::super::router(state);
	let (status, body) = request(
		&app,
		"POST",
		&format!("/api/v1/accounts/alice/archive/{id}/restore"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["id"], id.to_string());
	assert_eq!(body["restored_to"], "INBOX");

	// The archive no longer holds the entry.
	let entries = archive::list(&dir.path().join("accounts/alice")).expect("list");
	assert!(entries.is_empty());
	// The mailbox has the restored message.
	let snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		0,
		2_000,
	)
	.expect("snapshot");
	assert_eq!(snapshot.len(), 1);
}

#[tokio::test]
async fn archive_restore_returns_404_for_unknown_account() {
	let (_dir, state) = archive_test_state().await;
	let app = super::super::super::router(state);
	let id = uuid::Uuid::now_v7();
	let (status, _) = request(
		&app,
		"POST",
		&format!("/api/v1/accounts/nobody/archive/{id}/restore"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn archive_list_requires_authentication() {
	let (_dir, state) = archive_test_state().await;
	let app = super::super::super::router(state);
	let (status, _) = request(&app, "GET", "/api/v1/accounts/alice/archive", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}
