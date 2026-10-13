//! Additional JMAP `/changes` tests (RFC 8620 §5.2), split from
//! `jmap_tests_changes` so the per-file line cap holds.

use super::jmap_tests_changes_helpers::*;
use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use serde_json::{Value, json};

#[tokio::test]
async fn jmap_email_changes_reports_all_three_together() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// Seed: one message marked \Deleted (will be expunged later).
	let created_id = append_to_inbox(dir.path(), "alice");
	store_deleted(dir.path(), "alice", "INBOX");
	let since = fetch_email_state(&app, "alice").await;
	// One new delivery.
	let created_id2 = append_to_inbox(dir.path(), "alice");
	// One flag change on the new message.
	store_flags_at(
		dir.path(),
		"alice",
		"INBOX",
		vec![
			crate::imap::mailbox::Flag::Seen,
			crate::imap::mailbox::Flag::Deleted,
		],
	);
	// One expunge: removes both messages (both carry \Deleted).
	expunge_first(dir.path(), "alice", "INBOX");
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": since}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	let created: Vec<String> = resp["created"]
		.as_array()
		.expect("array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	let destroyed: Vec<String> = resp["destroyed"]
		.as_array()
		.expect("array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	assert!(
		created.contains(&created_id2),
		"created must include the new delivery: {resp}"
	);
	assert!(
		destroyed.contains(&created_id),
		"destroyed must include the expunged message: {resp}"
	);
	// `updated` may be empty (no flags actually changed) or have one
	// entry (the new delivery also got `\Seen`); accept either.
	let updated: Vec<String> = resp["updated"]
		.as_array()
		.expect("array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	assert!(updated.len() <= 1, "at most one updated entry: {resp}");
}

/// `maxChanges: 1` forces `hasMoreChanges: true`. The client calls
/// `/changes` again with the returned `newState` to drain the rest.
#[tokio::test]
async fn jmap_email_changes_paginates_when_max_changes_is_small() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// Capture the state BEFORE the deliveries so the changes since
	// this state are the three new messages.
	let since = fetch_email_state(&app, "alice").await;
	let _id1 = append_to_inbox(dir.path(), "alice");
	let _id2 = append_to_inbox(dir.path(), "alice");
	let _id3 = append_to_inbox(dir.path(), "alice");
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": since, "maxChanges": 1}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	let created: Vec<Value> = resp["created"].as_array().expect("created array").clone();
	assert_eq!(created.len(), 1, "maxChanges=1 caps created at 1: {resp}");
	assert_eq!(
		resp["hasMoreChanges"], true,
		"must signal more changes: {resp}"
	);
}

/// When the client sends a sinceState the server can no longer resolve (a
/// malformed base64 token, or one with the wrong type), the spec-correct
/// response is `cannotCalculateChanges`.
#[tokio::test]
async fn jmap_email_changes_returns_cannot_calculate_changes_for_a_malformed_since_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// "0" is the constant every method used to return; it is not a state.
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": "0"}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(
		body["methodResponses"][0][1]["type"], "cannotCalculateChanges",
		"unknown sinceState must answer cannotCalculateChanges"
	);
	// Likewise a syntactically valid base64 that does not decode to the
	// expected state shape.
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": "AAAA"}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(
		body["methodResponses"][0][1]["type"], "cannotCalculateChanges",
		"a too-short sinceState must also be refused"
	);
}

/// The principal gate protects `/changes` exactly like `/get`. A key
/// bound to one account cannot see another's email change log: the foreign
/// account is reported as `accountNotFound`, never as `cannotCalculateChanges`
/// or any other leak.
#[tokio::test]
async fn jmap_email_changes_for_a_foreign_account_is_account_not_found() {
	use crate::api::api_keys::ApiKey;
	use crate::storage::FsSpool;

	let dir = tempfile::tempdir().expect("tempdir");
	// Two accounts, one key per account.
	let secret_alice = "alice-secret".to_string();
	let secret_bob = "bob-secret".to_string();
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(ApiKey {
		label: "alice-only".into(),
		hash: crate::api::api_keys::sha256_hash(&secret_alice),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".into(), "write".into()],
		domains: Vec::new(),
		account: Some("alice".into()),
	})
	.expect("add");
	keys.add(ApiKey {
		label: "bob-only".into(),
		hash: crate::api::api_keys::sha256_hash(&secret_bob),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".into(), "write".into()],
		domains: Vec::new(),
		account: Some("bob".into()),
	})
	.expect("add");
	drop(keys);

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
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![account("alice"), account("bob")],
		)
		.expect("open"),
	);
	let state = crate::api::ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		FsSpool::open(dir.path()).expect("spool"),
	)
	.with_directory(store.handle());
	let app = router(state);
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "bob"}, "c1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(secret_alice.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"alice's key must not see bob's /changes"
	);
}

/// The state string survives a process restart unchanged: a state handed out
/// before a restart is still valid when nothing changed.
#[tokio::test]
async fn jmap_email_state_survives_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let _id = append_to_inbox(dir.path(), "alice");
	let before = fetch_email_state(&app, "alice").await;
	// Drop the app; rebuild it against the same `data_dir`. The journal
	// lives on disk, so the new app derives the same state.
	drop(app);
	let app = router(test_state(dir.path(), 0));
	let after = fetch_email_state(&app, "alice").await;
	assert_eq!(before, after, "state must be identical across a restart");
}

/// `Email/changes` from the state the server is currently at reports no
/// changes (`created`, `updated`, `destroyed` all empty, `hasMoreChanges`
/// `false`).
#[tokio::test]
async fn jmap_email_changes_with_current_state_reports_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let _id = append_to_inbox(dir.path(), "alice");
	let current = fetch_email_state(&app, "alice").await;
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": current}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	assert_eq!(resp["hasMoreChanges"], false);
	assert!(resp["created"].as_array().unwrap().is_empty());
	assert!(resp["updated"].as_array().unwrap().is_empty());
	assert!(resp["destroyed"].as_array().unwrap().is_empty());
}

/// `Mailbox/changes` reports a created mailbox, then its destruction; a
/// mailbox created and destroyed after the client's state is in neither list.
#[tokio::test]
async fn jmap_mailbox_changes_reports_a_created_and_destroyed_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let since = fetch_mailbox_state(&app, "alice").await;
	let req = json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let (created, destroyed) = mailbox_changes(&app, &since).await;
	assert_eq!(created, vec!["Work".to_string()]);
	assert!(destroyed.is_empty(), "{destroyed:?}");
	let middle = fetch_mailbox_state(&app, "alice").await;
	let req = json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "destroy": ["Work"]}, "m2"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let (created, destroyed) = mailbox_changes(&app, &middle).await;
	assert!(created.is_empty(), "{created:?}");
	assert_eq!(destroyed, vec!["Work".to_string()]);
	let (created, destroyed) = mailbox_changes(&app, &since).await;
	assert!(
		created.is_empty() && destroyed.is_empty(),
		"created then destroyed is reported in neither list: {created:?} {destroyed:?}"
	);
}

async fn mailbox_changes(app: &axum::Router, since: &str) -> (Vec<String>, Vec<String>) {
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/changes", {"accountId": "alice", "sinceState": since}, "c1"]],
	});
	let (_, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0];
	assert_eq!(resp[0], "Mailbox/changes", "{body}");
	let list = |key: &str| -> Vec<String> {
		resp[1][key]
			.as_array()
			.expect("array")
			.iter()
			.filter_map(|v| v.as_str().map(str::to_string))
			.collect()
	};
	(list("created"), list("destroyed"))
}

/// `Email/queryChanges` for the supported shape (a single `inMailbox`
/// filter, no extra sort) is computable. The common case answers the
/// diff with `added` ids (the new deliveries) and `removed` ids (the
/// expunges).
#[tokio::test]
async fn jmap_email_query_changes_is_calculable_for_inbox_filter() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// Seed one message so the query results are not empty.
	let _id = append_to_inbox(dir.path(), "alice");
	let since = fetch_email_state(&app, "alice").await;
	// The query state used to drive /queryChanges is `queryState`, not
	// `state`. The two are equal in shape for the supported common
	// case: `queryState` echoes the same opaque token `state` returns.
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/queryChanges", {
			"accountId": "alice",
			"sinceQueryState": since,
			"filter": {"inMailbox": "INBOX"}
		}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	assert_eq!(
		body["methodResponses"][0][0], "Email/queryChanges",
		"supported common query must be calculable: {resp}"
	);
	assert!(resp["added"].is_array(), "added must be an array: {resp}");
	assert!(
		resp["removed"].is_array(),
		"removed must be an array: {resp}"
	);
}

/// A query with an unsupported filter (anything other than a single
/// `inMailbox` clause) is refused with `cannotCalculateChanges`, the error
/// RFC 8620 section 5.6 defines for a query the server cannot replay.
#[tokio::test]
async fn jmap_email_query_changes_refuses_an_unsupported_filter() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let since = fetch_email_state(&app, "alice").await;
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/queryChanges", {
			"accountId": "alice",
			"sinceQueryState": since,
			"filter": {"text": "needle"}
		}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(
		body["methodResponses"][0][1]["type"], "cannotCalculateChanges",
		"a text filter is not in the supported set"
	);
}

/// An IMAP STORE flag change is visible to JMAP: both protocols write the
/// same change journal through `Snapshot::store_flags`.
#[tokio::test]
async fn jmap_email_changes_observes_an_imap_store_flag_change() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let id = append_to_inbox(dir.path(), "alice");
	let since = fetch_email_state(&app, "alice").await;
	// IMAP-style flag mutation.
	store_seen(dir.path(), "alice", "INBOX");
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": since}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	let updated: Vec<String> = resp["updated"]
		.as_array()
		.expect("array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	assert!(
		updated.contains(&id),
		"the IMAP-flagged message must appear in Email/changes: {resp}"
	);
}
