//! JMAP `/changes` tests (RFC 8620 §5.2).
//!
//! Test helpers (state fetchers, mailbox primitives) live in
//! `jmap_tests_changes_helpers.rs`. The per-file line cap forces the
//! split; the helpers are `pub(super)` so the tests here can use them.

use super::jmap_tests_changes_helpers::*;
use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use serde_json::json;

#[tokio::test]
async fn jmap_email_state_is_stable_when_nothing_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let s1 = fetch_email_state(&app, "alice").await;
	let s2 = fetch_email_state(&app, "alice").await;
	let s3 = fetch_email_state(&app, "alice").await;
	assert_eq!(s1, s2, "second state must equal first");
	assert_eq!(s2, s3, "third state must equal second");
	// The state is opaque to the client, but it is no longer the constant
	// `"0"` every method used to return.
	assert_ne!(
		s1, "0",
		"state must be the real opaque token, not the legacy constant"
	);
}

#[tokio::test]
async fn jmap_mailbox_state_is_stable_when_nothing_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let s1 = fetch_mailbox_state(&app, "alice").await;
	let s2 = fetch_mailbox_state(&app, "alice").await;
	assert_eq!(s1, s2);
	assert_ne!(s1, "0");
}

/// A new delivery advances the Email state. The same flag (IMAP STORE)
/// is picked up by JMAP because both protocols share the per-account
/// counter.
#[tokio::test]
async fn jmap_email_state_advances_on_a_new_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let before = fetch_email_state(&app, "alice").await;
	// Append a message directly through `mailbox::append` (the same
	// path SMTP and JMAP create use). The per-account counter must
	// move.
	let _id = append_to_inbox(dir.path(), "alice");
	let after = fetch_email_state(&app, "alice").await;
	assert_ne!(before, after, "delivery must advance Email state");
}

/// An IMAP flag change advances the Email state. The state is per-account,
/// not per-mailbox, so a STORE on INBOX is visible from `Email/get`
/// without the JMAP client polling anything else.
#[tokio::test]
async fn jmap_email_state_advances_on_an_imap_flag_change() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let _id = append_to_inbox(dir.path(), "alice");
	let before = fetch_email_state(&app, "alice").await;
	store_seen(dir.path(), "alice", "INBOX");
	let after = fetch_email_state(&app, "alice").await;
	assert_ne!(
		before, after,
		"IMAP STORE must advance the JMAP Email state"
	);
}

/// An IMAP expunge advances the Email state.
#[tokio::test]
async fn jmap_email_state_advances_on_an_imap_expunge() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let _id = append_to_inbox(dir.path(), "alice");
	// Mark \Deleted so the next expunge actually removes the message.
	store_deleted(dir.path(), "alice", "INBOX");
	let before = fetch_email_state(&app, "alice").await;
	expunge_first(dir.path(), "alice", "INBOX");
	let after = fetch_email_state(&app, "alice").await;
	assert_ne!(
		before, after,
		"IMAP EXPUNGE must advance the JMAP Email state"
	);
}

/// A mailbox create / rename / destroy advances the Mailbox state. The
/// IMAP per-mailbox modseqctr is not bumped on create, so this exercises
/// the dedicated mailbox-set version counter.
#[tokio::test]
async fn jmap_mailbox_state_advances_on_create_rename_and_destroy() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let s0 = fetch_mailbox_state(&app, "alice").await;
	// Create
	let req = json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert!(
		body["methodResponses"][0][1]["created"]["c"]["id"].is_string(),
		"create must succeed: {body}"
	);
	let s1 = fetch_mailbox_state(&app, "alice").await;
	assert_ne!(s0, s1, "create must advance Mailbox state");
	// Rename
	let req = json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "update": {"Work": {"name": "Projects"}}}, "m2"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let s2 = fetch_mailbox_state(&app, "alice").await;
	assert_ne!(s1, s2, "rename must advance Mailbox state");
	// Destroy
	let req = json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "destroy": ["Projects"]}, "m3"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let s3 = fetch_mailbox_state(&app, "alice").await;
	assert_ne!(s2, s3, "destroy must advance Mailbox state");
}

/// `Email/changes` from a state captured before a delivery reports the
/// delivery as a `created` id. The `newState` is the post-delivery state,
/// and `hasMoreChanges` is `false`.
#[tokio::test]
async fn jmap_email_changes_reports_a_new_delivery_as_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let since = fetch_email_state(&app, "alice").await;
	let id = append_to_inbox(dir.path(), "alice");
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": since}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	assert_eq!(body["methodResponses"][0][0], "Email/changes");
	assert_eq!(resp["accountId"], "alice");
	assert_eq!(resp["hasMoreChanges"], false);
	let created: Vec<String> = resp["created"]
		.as_array()
		.expect("created array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	assert!(
		created.contains(&id),
		"created must include the new message: {resp}"
	);
	assert!(
		resp["updated"].as_array().is_some_and(|a| a.is_empty()),
		"updated must be empty: {resp}"
	);
	assert!(
		resp["destroyed"].as_array().is_some_and(|a| a.is_empty()),
		"destroyed must be empty: {resp}"
	);
}

/// A flag change on a message that already existed at `sinceState` is
/// reported as `updated`. The `.created` sidecar is the discriminator
/// between a fresh delivery (created) and a flag-only update (updated).
#[tokio::test]
async fn jmap_email_changes_reports_a_flag_change_as_updated() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let id = append_to_inbox(dir.path(), "alice");
	// Capture the state AFTER the delivery so the message already existed.
	let since = fetch_email_state(&app, "alice").await;
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
		.expect("updated array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	assert!(
		updated.contains(&id),
		"updated must include the flag-changed message: {resp}"
	);
	assert!(
		resp["created"].as_array().is_some_and(|a| a.is_empty()),
		"created must be empty: {resp}"
	);
}

/// An expunge is reported in `destroyed`, by the message's UUID. The
/// vanished log carries the UUID column specifically so JMAP clients
/// see the same id they used before the expunge.
#[tokio::test]
async fn jmap_email_changes_reports_an_expunge_as_destroyed() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let id = append_to_inbox(dir.path(), "alice");
	// Mark \Deleted so the next expunge removes the message.
	store_deleted(dir.path(), "alice", "INBOX");
	let since = fetch_email_state(&app, "alice").await;
	expunge_first(dir.path(), "alice", "INBOX");
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/changes", {"accountId": "alice", "sinceState": since}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	let destroyed: Vec<String> = resp["destroyed"]
		.as_array()
		.expect("destroyed array")
		.iter()
		.filter_map(|v| v.as_str().map(str::to_string))
		.collect();
	assert!(
		destroyed.contains(&id),
		"destroyed must include the expunged message: {resp}"
	);
}
