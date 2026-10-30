//! The migration that is interrupted and resumed: the confirmed prefix, the
//! unclaimed copies, the limits of the recovery index and the barriers that
//! have to hold before a checkpoint is written.

use super::*;
use crate::migrate::imap::MigrateError;
use crate::migrate::imap::durability;
use crate::migrate::imap::state::{FolderState, StateDir};

#[tokio::test]
async fn recovery_preserves_identical_messages_after_a_confirmed_prefix() {
	let dir = tempfile::tempdir().expect("dir");
	let target = target(dir.path());
	crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], b"a", &target.crypto)
		.expect("confirmed message");
	let states = StateDir::open(dir.path(), "alice", "alice@old.example").expect("states");
	states
		.save(
			b"INBOX",
			&FolderState {
				folder: "INBOX".into(),
				uid_validity: 7,
				last_uid: 1,
				in_progress: true,
				copied: 1,
			},
		)
		.expect("pending batch");
	let (summary, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "resume failed: {error:?}");
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"both remote copies must survive"
	);
	assert_eq!(summary.copied, 1);
	let (summary, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "repeat failed: {error:?}");
	assert_eq!(summary.copied, 0);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_second_interruption_keeps_recovery_active_for_unclaimed_copies() {
	let dir = tempfile::tempdir().expect("dir");
	let target = target(dir.path());
	for _ in 0..2 {
		crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], b"a", &target.crypto)
			.expect("stored message");
	}
	let states = StateDir::open(dir.path(), "alice", "alice@old.example").expect("states");
	states
		.save(
			b"INBOX",
			&FolderState {
				folder: "INBOX".into(),
				uid_validity: 7,
				last_uid: 1,
				in_progress: true,
				copied: 1,
			},
		)
		.expect("pending batch");
	let (_, error) = migrate_memory(dir.path(), true, None).await;
	assert!(matches!(error, Some(MigrateError::Timeout)));
	assert!(
		states
			.load(b"INBOX")
			.expect("load")
			.expect("state")
			.in_progress,
		"a partial replay must still account for unclaimed local copies"
	);
	let (_, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "resume failed: {error:?}");
	assert_eq!(local(dir.path(), "INBOX").len(), 2);
}

#[tokio::test]
async fn recovery_index_obeys_mailbox_and_total_metadata_limits() {
	for (validity, pending, scope) in [
		(7, true, "mailbox"),
		(6, false, "mailbox"),
		(6, false, "total"),
	] {
		let dir = tempfile::tempdir().expect("dir");
		let target = target(dir.path());
		for number in 0..8 {
			let body = format!("Message-ID: <{number}{}>\r\n\r\na", "x".repeat(4096));
			crate::imap::mailbox::append(
				dir.path(),
				"alice",
				"INBOX",
				&[],
				body.as_bytes(),
				&target.crypto,
			)
			.expect("local message");
		}
		let states = StateDir::open(dir.path(), "alice", "alice@old.example").expect("states");
		let saved = FolderState {
			folder: "INBOX".into(),
			uid_validity: validity,
			last_uid: 1,
			in_progress: pending,
			copied: 1,
		};
		states.save(b"INBOX", &saved).expect("save");
		let limits = if scope == "mailbox" {
			(8192, usize::MAX)
		} else {
			(usize::MAX, 8192)
		};
		let (_, error) = migrate_with_budget(dir.path(), false, Some(limits)).await;
		assert!(
			matches!(error, Some(MigrateError::Client(ClientError::Metadata { scope: actual, .. })) if actual == scope),
			"recovery index must charge {scope} metadata: {error:?}"
		);
		assert_eq!(
			states.load(b"INBOX").expect("load"),
			Some(saved),
			"keep the resumable checkpoint"
		);
		let (summary, error) = migrate_memory(dir.path(), false, None).await;
		assert!(error.is_none(), "resume with sufficient budget: {error:?}");
		assert_eq!(summary.copied, 2);
	}
}

#[tokio::test]
async fn message_durability_precedes_each_confirmed_checkpoint() {
	let dir = tempfile::tempdir().expect("dir");
	let _guard = durability::tests::base::begin(None);
	let (_, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "migration failed: {error:?}");
	let events = durability::tests::base::events();
	let first = events
		.iter()
		.position(|event| *event == "state-file")
		.expect("state sync");
	assert!(
		events[first.saturating_sub(2)..first] == ["state-parent", "state-parent"],
		"make both state directory entries durable before publishing state: {events:?}"
	);
	let positions: Vec<_> = events
		.iter()
		.enumerate()
		.filter_map(|(i, e)| (*e == "message").then_some(i))
		.collect();
	assert_eq!(
		positions.len(),
		2,
		"synchronize both stored messages: {events:?}"
	);
	for position in positions {
		let checkpoint = position
			+ events[position..]
				.iter()
				.position(|event| *event == "state-file")
				.expect("next checkpoint");
		assert_eq!(
			&events[position..position + 4],
			&["message", "flags", "zone", "mailbox-directory"]
		);
		assert!(
			events[position..checkpoint].contains(&"mailbox-parent"),
			"persist the mailbox hierarchy before checkpointing"
		);
		assert!(
			events[position..checkpoint].contains(&"ledger-file"),
			"record what the batch confirmed before the checkpoint: {events:?}"
		);
	}
}

#[tokio::test]
async fn failed_message_sync_keeps_recovery_active_and_resumes_without_duplication() {
	for barrier in [
		"message",
		"flags",
		"zone",
		"mailbox-directory",
		"mailbox-parent",
	] {
		let dir = tempfile::tempdir().expect("dir");
		let guard = durability::tests::base::begin(Some(barrier));
		let (_, error) = migrate_memory(dir.path(), false, None).await;
		assert!(
			matches!(error, Some(MigrateError::Storage(_))),
			"refuse to confirm failed {barrier} sync: {error:?}"
		);
		let states = StateDir::open(dir.path(), "alice", "alice@old.example").expect("states");
		let saved = states.load(b"INBOX").expect("load").expect("state");
		assert_eq!(
			saved.last_uid, 0,
			"do not confirm an unsynchronized message"
		);
		assert!(
			saved.in_progress,
			"an unconfirmed stored message needs recovery"
		);
		drop(guard);
		let (_, error) = migrate_memory(dir.path(), false, None).await;
		assert!(error.is_none(), "resume failed: {error:?}");
		assert_eq!(
			local(dir.path(), "INBOX").len(),
			2,
			"claim the unconfirmed copy during recovery"
		);
	}
}

#[tokio::test]
async fn recovery_sync_failure_precedes_any_checkpoint_write() {
	for barrier in [
		"message",
		"flags",
		"zone",
		"mailbox-directory",
		"mailbox-parent",
	] {
		let dir = tempfile::tempdir().expect("dir");
		let (_, error) = migrate_memory(dir.path(), false, None).await;
		assert!(error.is_none());
		let states = StateDir::open(dir.path(), "alice", "alice@old.example").expect("states");
		let mut saved = states.load(b"INBOX").expect("load").expect("state");
		saved.last_uid = 1;
		saved.in_progress = true;
		states.save(b"INBOX", &saved).expect("save");
		let guard = durability::tests::base::begin(Some(barrier));
		let (_, error) = migrate_memory(dir.path(), false, None).await;
		assert!(
			matches!(error, Some(MigrateError::Storage(_))),
			"recovery must synchronize {barrier}: {error:?}"
		);
		assert!(
			!durability::tests::base::events().contains(&"state-file"),
			"do not checkpoint before recovery copies are durable"
		);
		assert_eq!(states.load(b"INBOX").expect("load"), Some(saved));
		drop(guard);
		let (_, error) = migrate_memory(dir.path(), false, None).await;
		assert!(error.is_none(), "resume failed: {error:?}");
		assert_eq!(local(dir.path(), "INBOX").len(), 2);
	}
}
