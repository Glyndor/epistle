//! JMAP `/changes` regressions: ordering across mailboxes, pagination that
//! resumes without losing changes, and mailbox events made outside JMAP.

use super::base::{TOKEN, request_with_body, test_state};
use super::jmap_changes_helpers::*;
use super::router;
use serde_json::{Value, json};

async fn call(app: &axum::Router, method: &str, args: Value) -> Value {
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [[method, args, "c1"]],
	});
	let (_, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	body["methodResponses"][0].clone()
}

fn ids(value: &Value) -> Vec<String> {
	value
		.as_array()
		.map(|list| {
			list.iter()
				.filter_map(|v| v.as_str().map(str::to_string))
				.collect()
		})
		.unwrap_or_default()
}

fn append_to(data_dir: &std::path::Path, mailbox: &str) -> String {
	crate::imap::mailbox::append(
		data_dir,
		"alice",
		mailbox,
		&[],
		b"From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("append")
	.to_string()
}

fn setup() -> (tempfile::TempDir, axum::Router) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice").join("new")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	(dir, app)
}

/// A delivery into a quiet folder after a lot of INBOX activity must still
/// be reported: the change position is account-wide, not per mailbox.
#[tokio::test]
async fn email_changes_reports_a_folder_delivery_after_inbox_activity() {
	let (dir, app) = setup();
	crate::imap::mailbox::create(dir.path(), "alice", "Work").expect("create");
	for _ in 0..4 {
		append_to(dir.path(), "INBOX");
	}
	for _ in 0..4 {
		store_seen(dir.path(), "alice", "INBOX");
		store_flags_at(dir.path(), "alice", "INBOX", Vec::new());
	}
	let since = fetch_email_state(&app, "alice").await;
	let fresh = append_to(dir.path(), "Work");
	let resp = call(
		&app,
		"Email/changes",
		json!({"accountId": "alice", "sinceState": since}),
	)
	.await;
	assert_eq!(
		ids(&resp[1]["created"]),
		vec![fresh],
		"the folder delivery must be the only created id: {resp}"
	);
	assert_eq!(ids(&resp[1]["updated"]), Vec::<String>::new(), "{resp}");
}

/// With `maxChanges` smaller than the backlog, every page returns an
/// intermediate `newState`, and following them yields every change once.
#[tokio::test]
async fn email_changes_pages_resume_without_losing_changes() {
	let (dir, app) = setup();
	let mut since = fetch_email_state(&app, "alice").await;
	let expected: Vec<String> = (0..3).map(|_| append_to(dir.path(), "INBOX")).collect();
	let final_state = fetch_email_state(&app, "alice").await;
	let mut seen: Vec<String> = Vec::new();
	let mut pages = 0;
	loop {
		pages += 1;
		assert!(pages <= 5, "pagination must terminate");
		let resp = call(
			&app,
			"Email/changes",
			json!({"accountId": "alice", "sinceState": since, "maxChanges": 1}),
		)
		.await;
		let created = ids(&resp[1]["created"]);
		assert!(created.len() <= 1, "maxChanges caps each page: {resp}");
		seen.extend(created);
		since = resp[1]["newState"].as_str().expect("newState").to_string();
		if resp[1]["hasMoreChanges"] != true {
			break;
		}
		assert_ne!(
			since, final_state,
			"a partial page must not jump to the final state: {resp}"
		);
	}
	assert_eq!(seen, expected, "every created id exactly once, in order");
	assert_eq!(
		since, final_state,
		"the last page ends at the current state"
	);
}

/// A mailbox id is its name, so a rename is the old id destroyed and the new
/// id created; reporting the old id as updated would send the client to a
/// mailbox that no longer exists.
#[tokio::test]
async fn mailbox_changes_reports_a_rename_as_destroy_and_create() {
	let (dir, app) = setup();
	crate::imap::mailbox::create(dir.path(), "alice", "Work").expect("create");
	let since = fetch_mailbox_state(&app, "alice").await;
	crate::imap::mailbox::rename(dir.path(), "alice", "Work", "Projects").expect("rename");
	let resp = call(
		&app,
		"Mailbox/changes",
		json!({"accountId": "alice", "sinceState": since}),
	)
	.await;
	assert_eq!(
		ids(&resp[1]["created"]),
		vec!["Projects".to_string()],
		"{resp}"
	);
	assert_eq!(
		ids(&resp[1]["destroyed"]),
		vec!["Work".to_string()],
		"{resp}"
	);
	assert_eq!(ids(&resp[1]["updated"]), Vec::<String>::new(), "{resp}");
}

/// A mailbox created over IMAP is reported by `Mailbox/changes`.
#[tokio::test]
async fn mailbox_changes_reports_a_mailbox_created_outside_jmap() {
	let (dir, app) = setup();
	let since = fetch_mailbox_state(&app, "alice").await;
	crate::imap::mailbox::create(dir.path(), "alice", "Receipts").expect("create");
	let resp = call(
		&app,
		"Mailbox/changes",
		json!({"accountId": "alice", "sinceState": since}),
	)
	.await;
	assert_eq!(
		ids(&resp[1]["created"]),
		vec!["Receipts".to_string()],
		"{resp}"
	);
}

/// A delivery changes INBOX's counts: the Mailbox state moves and
/// `Mailbox/changes` reports INBOX as updated with the count properties as
/// a flat array (RFC 8621 section 2.2).
#[tokio::test]
async fn mailbox_changes_reports_count_changes_with_updated_properties() {
	let (dir, app) = setup();
	let since = fetch_mailbox_state(&app, "alice").await;
	append_to(dir.path(), "INBOX");
	let resp = call(
		&app,
		"Mailbox/changes",
		json!({"accountId": "alice", "sinceState": since}),
	)
	.await;
	assert_eq!(
		ids(&resp[1]["updated"]),
		vec!["INBOX".to_string()],
		"{resp}"
	);
	assert_eq!(
		resp[1]["updatedProperties"],
		json!([
			"totalEmails",
			"unreadEmails",
			"totalThreads",
			"unreadThreads"
		]),
		"{resp}"
	);
}
