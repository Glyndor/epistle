//! Test helpers for the JMAP /changes tests.
//!
//! The state fetchers and IMAP primitives shared by the `jmap_tests_changes`
//! and `jmap_tests_changes_b` files live here. The split keeps each
//! test file under the per-file line cap without losing any test.

#[allow(unused_imports)]
use super::router;
#[allow(unused_imports)]
use super::tests::{TOKEN, request_with_body, test_state};
use serde_json::json;

/// Fetch the current Email state of an account through `Email/get`. The
/// response shape is the contract the test asserts against.
pub(super) async fn fetch_email_state(app: &axum::Router, account: &str) -> String {
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/get", {"accountId": account}, "c1"]],
	});
	let (_, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	body["methodResponses"][0][1]["state"]
		.as_str()
		.expect("Email/get state is a string")
		.to_string()
}

/// Fetch the current Mailbox state.
pub(super) async fn fetch_mailbox_state(app: &axum::Router, account: &str) -> String {
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", {"accountId": account}, "c1"]],
	});
	let (_, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	body["methodResponses"][0][1]["state"]
		.as_str()
		.expect("Mailbox/get state is a string")
		.to_string()
}

/// Append a message directly through the IMAP mailbox helper, bypassing
/// the JMAP layer, to keep the test focused on what `Email/changes`
/// observes when something happens that the JMAP layer did not initiate.
pub(super) fn append_to_inbox(data_dir: &std::path::Path, account: &str) -> String {
	crate::imap::mailbox::append(
		data_dir,
		account,
		"INBOX",
		&[],
		b"From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("append")
	.to_string()
}

/// Mark `\Seen` on the first message of a mailbox (the IMAP STORE path).
pub(super) fn store_seen(data_dir: &std::path::Path, account: &str, mailbox: &str) {
	store_flags_at(
		data_dir,
		account,
		mailbox,
		vec![crate::imap::mailbox::Flag::Seen],
	);
}

/// Mark `\Deleted` on the first message of a mailbox, so a subsequent
/// `snapshot.expunge()` actually removes it.
pub(super) fn store_deleted(data_dir: &std::path::Path, account: &str, mailbox: &str) {
	store_flags_at(
		data_dir,
		account,
		mailbox,
		vec![crate::imap::mailbox::Flag::Deleted],
	);
}

pub(super) fn store_flags_at(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	flags: Vec<crate::imap::mailbox::Flag>,
) {
	let mut snapshot = crate::imap::mailbox::Snapshot::open(
		data_dir,
		account,
		mailbox,
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	snapshot.store_flags(1, flags).expect("store");
}

/// Expunge the first message of a mailbox.
pub(super) fn expunge_first(data_dir: &std::path::Path, account: &str, mailbox: &str) {
	let mut snapshot = crate::imap::mailbox::Snapshot::open(
		data_dir,
		account,
		mailbox,
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	snapshot.expunge().expect("expunge");
}
