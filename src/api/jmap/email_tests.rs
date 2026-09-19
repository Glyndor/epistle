//! Tests for `apply_email_update`: the JMAP `Email/set` keyword and
//! mailbox-move transition. Split out of `email.rs` so the module
//! stays under the per-file line cap.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::antispam::trainer::RecordingTrainer;
use crate::imap::mailbox;
use crate::storage::MessageCrypto;

/// Build an [`ApiState`] whose `training()` returns a queue backed by
/// a [`RecordingTrainer`]. Two state-builders already exist
/// (`api_tests::test_state`) but neither wires a training queue, so
/// the JMAP-side tests roll their own here rather than overload the
/// generic one.
fn state_with_recording_training(
	dir: &std::path::Path,
) -> (ApiState, Arc<RecordingTrainer>) {
	let trainer = Arc::new(RecordingTrainer::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let queue = crate::antispam::training_queue::TrainingQueue::start(
		Arc::clone(&trainer) as Arc<dyn crate::antispam::trainer::BayesTrainer>,
		MessageCrypto::disabled(),
		Arc::clone(&metrics),
	);
	let spool = crate::storage::FsSpool::open(dir).expect("spool");
	let accounts = vec![crate::config::Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some("$argon2id$placeholder".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}];
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::hash("dummy"),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store,
		spool,
	)
	.with_training(queue);
	(state, trainer)
}

/// Seed one message in INBOX so `apply_email_update` can find it.
fn seed_inbox(dir: &std::path::Path, body: &[u8]) -> uuid::Uuid {
	mailbox::append(
		dir,
		"alice",
		"INBOX",
		&[crate::imap::mailbox::Flag::parse("$seen").expect("parse seen")],
		body,
		&MessageCrypto::disabled(),
	)
	.expect("append")
}

/// A combined "mark as junk and move to Junk" JMAP `Email/set` update
/// queues a spam-training job against the destination message. The
/// pre-fix code returned from the move branch without ever touching
/// the queue, so a re-mark was a no-op and the spam the user
/// intended to teach stayed in their corpus as `0`. The
/// `RecordingTrainer` only sees a `train` call when the worker
/// drains a job with a readable file, so an empty recording means
/// the worker hit the deleted source path and bailed out.
#[tokio::test]
async fn a_move_with_junk_keyword_queues_a_training_job_on_the_destination() {
	let dir = tempfile::tempdir().expect("tempdir");
	let body = b"Subject: hi\r\n\r\nbody\r\n";
	let id = seed_inbox(dir.path(), body);
	let (state, trainer) = state_with_recording_training(dir.path());

	let patch = json!({
		"mailboxIds": { "Junk": true },
		"keywords": { "$junk": true },
	});
	apply_email_update(&state, "alice", &id.to_string(), &patch).expect("update applies");

	// The message must now live under Junk, not INBOX. A fresh copy
	// was appended during the move, so the new entry carries a
	// different UUID from the source — what matters is the count
	// and the flag set, not that the id survived.
	let inbox_msgs: Vec<_> = mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
	)
	.expect("open INBOX")
	.messages()
	.map(|m| m.id().to_string())
	.collect();
	assert!(
		inbox_msgs.is_empty(),
		"the message should have moved out of INBOX; got: {inbox_msgs:?}"
	);
	let junk_snap = mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"Junk",
		&MessageCrypto::disabled(),
	)
	.expect("open Junk");
	let junk_msgs: Vec<_> = junk_snap
		.messages()
		.map(|m| (m.id().to_string(), m.flags.len()))
		.collect();
	assert_eq!(
		junk_msgs.len(),
		1,
		"the message should now live under Junk, got: {junk_msgs:?}"
	);
	let junk_message = junk_snap
		.messages()
		.next()
		.expect("at least one junk message");
	assert!(
		junk_message.flags.iter().any(|f| match f {
			crate::imap::mailbox::Flag::Keyword(k) if k.is_junk() => true,
			_ => false,
		}),
		"the moved message should carry the $Junk keyword, got flags: {:?}",
		junk_message.flags
	);

	// The training worker records the calls it sees; one spam
	// training call against the destination message is the fixed
	// behaviour. The recorded length pins the path: the worker only
	// hands the bytes to the trainer when it can read the file, so
	// the source path (already removed) would have surfaced as zero
	// recorded calls.
	let received = tokio::time::timeout(
		std::time::Duration::from_millis(500),
		trainer.await_one_call(),
	)
	.await;
	assert!(
		received.is_ok(),
		"the combined move+junk update must enqueue a spam training call: pre-fix returned without queueing"
	);
	let calls = trainer.calls();
	assert_eq!(
		calls.len(),
		1,
		"the combined move+junk update must queue exactly one spam training call: {calls:?}"
	);
	let (account, length, spam) = &calls[0];
	assert_eq!(account, "alice");
	assert_eq!(*length, body.len(), "worker loaded the destination body");
	assert!(spam, "spam side for added $Junk");
}
