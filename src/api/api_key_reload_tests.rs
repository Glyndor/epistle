//! Tests for the api_keys.toml hot-reload through the file watcher.
//!
//! The bearer middleware reads the running key set on every request; the
//! CLI is a sibling process that mutates the on-disk `api_keys.toml`
//! while the server is running. The watcher polls the file the same way
//! it polls `accounts.toml`, parses the new contents, and asks the API
//! state to swap. A revocation that does not revoke (until restart) is
//! the bug these tests guard against.

use std::sync::Arc;

use super::tests::{request, test_state};
use super::*;
use axum::http::StatusCode;

/// Build a read-scoped, IP-unrestricted key for a tempdir fixture.
fn read_key(secret: &str) -> crate::api::ApiKey {
	crate::api::ApiKey {
		label: "ci".to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string()],
		domains: Vec::new(),
	}
}

/// Build an `AccountStore` whose directory handle can be shared with the
/// file watcher. Mirrors `super::tests::test_state`'s setup so the watcher
/// has something to reload against.
fn account_store(dir: &std::path::Path) -> Arc<crate::directory_store::AccountStore> {
	let accounts = crate::config::Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![accounts],
		)
		.expect("account store"),
	)
}

/// Build the `Arc<ApiKeySet>` shared by `ApiState` and the file watcher.
/// Both must reference the same set; otherwise a reload from the watcher
/// would update a set the bearer middleware never reads.
fn api_keys(dir: &std::path::Path) -> Arc<crate::api::ApiKeySet> {
	Arc::new(crate::api::ApiKeySet::open(dir).unwrap_or_else(|_| crate::api::ApiKeySet::empty()))
}

/// Build a file watcher wired to the shared `ApiKeySet`. Seed-poll once
/// so the next poll sees fingerprints that differ from the on-startup view.
fn build_watcher(
	dir: &std::path::Path,
	store: Arc<crate::directory_store::AccountStore>,
	keys: Arc<crate::api::ApiKeySet>,
) -> crate::directory_store::FileWatcher {
	let mut watcher =
		crate::directory_store::FileWatcher::new(dir.to_path_buf(), Arc::clone(&store))
			.with_api_keys(
				Arc::clone(&keys) as Arc<dyn crate::directory_store::file_watcher::ApiKeyReloader>
			);
	let _ = watcher.poll();
	watcher
}

/// A key added through the same `ApiKeyStore::add` path the CLI uses
/// is honored by the running server on the very next watcher poll,
/// without restarting the process.
#[tokio::test]
async fn new_key_works_without_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = api_keys(dir.path());
	let app = router(test_state(dir.path(), 0).with_api_keys(Arc::clone(&keys)));
	let store = account_store(dir.path());
	let mut watcher = build_watcher(dir.path(), store, Arc::clone(&keys));

	// Pre-state: a secret the file knows nothing about is rejected.
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("ci-secret")).await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"before adding the key the server must reject the secret",
	);

	// CLI path: write the file via the same store the dispatcher uses.
	{
		let mut store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
		store.add(read_key("ci-secret")).expect("add key");
	}

	// Drive the poll explicitly: no sleep, no spawned task, the whole
	// point of the test is that one poll after the write is enough.
	let _ = watcher.poll();

	// Post-state: the new secret is accepted on the next request.
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("ci-secret")).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"after the watcher polls the new key must authenticate",
	);
}

/// Revoking a key through the same `ApiKeyStore::remove` path the CLI
/// uses is reflected on the next watcher poll, without restarting the
/// process. A revocation that does not revoke (until restart) is the
/// bug this test guards against.
#[tokio::test]
async fn revoked_key_is_rejected_after_watcher_poll() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Plant the key on disk first; `test_state` reads the file at
	// construction, so the running state sees it from request 1.
	{
		let mut store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
		store.add(read_key("ci-secret")).expect("add key");
	}
	let keys = api_keys(dir.path());
	let app = router(test_state(dir.path(), 0).with_api_keys(Arc::clone(&keys)));
	let store = account_store(dir.path());
	let mut watcher = build_watcher(dir.path(), store, Arc::clone(&keys));

	// Sanity: the key authenticates before the revocation.
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("ci-secret")).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"key must authenticate before revocation",
	);

	// Revoke through the same path the CLI uses.
	{
		let mut store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
		store.remove("ci").expect("revoke key");
	}

	let _ = watcher.poll();

	// The key no longer authenticates after the next poll.
	let (status, body) = request(&app, "GET", "/api/v1/status", Some("ci-secret")).await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"after revoke + poll the key must stop authenticating (got body: {body})",
	);
	assert_eq!(
		body["error"]["code"], "unauthenticated",
		"rejection must come from the auth middleware, not a routing fallback",
	);
}

/// A bad file (e.g. a half-written operator edit) does NOT replace the
/// running key set. The last good set keeps authenticating until the
/// file recovers, and the watcher logs exactly one warning per bad
/// version instead of spamming on every poll.
#[tokio::test]
async fn bad_file_keeps_the_old_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Plant the good key.
	{
		let mut store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
		store.add(read_key("ci-secret")).expect("add key");
	}
	let keys = api_keys(dir.path());
	let app = router(test_state(dir.path(), 0).with_api_keys(Arc::clone(&keys)));
	let store = account_store(dir.path());
	let mut watcher = build_watcher(dir.path(), store, Arc::clone(&keys));

	// Sanity: good state authenticates the key.
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("ci-secret")).await;
	assert_eq!(status, StatusCode::OK, "good key authenticates");

	// Operator (or a crashed write) leaves the file with invalid TOML.
	crate::storage::write_secret(
		&dir.path().join("api_keys.toml"),
		b"this is not = = valid toml",
	)
	.expect("write bad");

	let report = watcher.poll();
	assert!(
		report.events.iter().any(|event| matches!(
			event,
			crate::directory_store::file_watcher::PollEvent::BadParse(
				crate::directory_store::file_watcher::PollTarget::ApiKeys,
			)
		)),
		"the bad api_keys.toml must be reported as a parse failure: {report:?}",
	);

	// The good key still authenticates: a bad reload must not wipe the
	// running set, otherwise an operator's typo would lock everyone out.
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("ci-secret")).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"a bad api_keys.toml must not invalidate the running key set",
	);
}
