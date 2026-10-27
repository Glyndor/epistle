//! Sequence numbers reported when messages leave a snapshot. Each one is
//! valid at the moment it is sent, so removing an earlier message renumbers
//! every later one.

use super::*;
use crate::storage::MessageCrypto;

fn deliver(dir: &Path, account: &str, body: &[u8]) -> Uuid {
	let new_dir = dir.join("accounts").join(account).join("new");
	std::fs::create_dir_all(&new_dir).expect("create dirs");
	let id = Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
	id
}

/// A mailbox of five messages, uids 1 to 5, in delivery order.
fn five_messages(dir: &Path) -> Snapshot {
	for body in [b"a\r\n", b"b\r\n", b"c\r\n", b"d\r\n", b"e\r\n"] {
		deliver(dir, "alice", body);
	}
	Snapshot::open(dir, "alice", "INBOX", &MessageCrypto::disabled()).expect("snapshot")
}

fn bodies(snapshot: &Snapshot) -> Vec<Vec<u8>> {
	snapshot
		.messages()
		.map(|message| snapshot.read(message).expect("read"))
		.collect()
}

#[test]
fn expunge_uids_reports_renumbered_sequences_and_keeps_the_rest_in_order() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut snapshot = five_messages(dir.path());
	for sequence in [2, 4, 5] {
		snapshot
			.store_flags(sequence, vec![Flag::Deleted])
			.expect("store");
	}
	let expunged = snapshot.expunge_uids(&[2, 5]).expect("expunge uids");
	assert_eq!(expunged, vec![2, 4], "uids 2 and 5 sat at 2 and (after) 4");
	assert_eq!(
		bodies(&snapshot),
		vec![b"a\r\n".to_vec(), b"c\r\n".to_vec(), b"d\r\n".to_vec()]
	);
	let uids: Vec<u32> = snapshot.messages().map(|m| m.uid).collect();
	assert_eq!(uids, vec![1, 3, 4], "uid 4 stays, it was never selected");
}

#[test]
fn remove_uids_ignores_the_deleted_flag_and_reports_increasing_sequences() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut snapshot = five_messages(dir.path());
	let removed = snapshot.remove_uids(&[1, 2, 4]).expect("remove uids");
	assert_eq!(removed, vec![1, 1, 2], "each sequence is valid when sent");
	assert_eq!(
		bodies(&snapshot),
		vec![b"c\r\n".to_vec(), b"e\r\n".to_vec()]
	);
	let reopened =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("snapshot");
	assert_eq!(reopened.len(), 2, "the removed files are gone from disk");
}

#[test]
fn remove_uids_with_no_match_changes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut snapshot = five_messages(dir.path());
	let removed = snapshot.remove_uids(&[99]).expect("remove uids");
	assert!(removed.is_empty());
	assert_eq!(snapshot.len(), 5);
}

#[test]
fn remove_at_drops_exactly_the_message_at_that_sequence() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut snapshot = five_messages(dir.path());
	snapshot.remove_at(3).expect("remove");
	assert_eq!(
		bodies(&snapshot),
		vec![
			b"a\r\n".to_vec(),
			b"b\r\n".to_vec(),
			b"d\r\n".to_vec(),
			b"e\r\n".to_vec()
		]
	);
	assert!(
		snapshot.remove_at(5).is_err(),
		"sequence 5 no longer exists"
	);
	assert!(snapshot.remove_at(0).is_err(), "sequences start at 1");
	assert_eq!(snapshot.len(), 4);
}

/// An expunge in a folder is logged for `VANISHED (EARLIER)` exactly like one
/// in INBOX: the folder's log path is not mistaken for an account path.
#[test]
fn expunge_in_a_folder_logs_vanished_uids() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"inbox\r\n");
	create(dir.path(), "alice", "Work").expect("create folder");
	let crypto = MessageCrypto::disabled();
	append(dir.path(), "alice", "Work", &[], b"one\r\n", &crypto).expect("append");
	let mut snapshot = Snapshot::open(dir.path(), "alice", "Work", &crypto).expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("store");
	let base = snapshot.highest_modseq();
	snapshot.expunge().expect("expunge");
	let folder_dir = mailbox_dir(dir.path(), "alice", "Work").expect("folder dir");
	assert_eq!(
		crate::imap::vanished::since(&folder_dir, base),
		vec![1],
		"the folder expunge must be in the folder's vanished log"
	);
}

/// Deleting a mailbox destroys its messages for JMAP as well as the mailbox.
#[test]
fn deleting_a_mailbox_records_its_messages_as_destroyed() {
	use crate::imap::changelog::Change;
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"inbox\r\n");
	create(dir.path(), "alice", "Old").expect("create folder");
	let crypto = MessageCrypto::disabled();
	let id = append(dir.path(), "alice", "Old", &[], b"one\r\n", &crypto).expect("append");
	let root = dir.path().join("accounts").join("alice");
	let before = crate::imap::changelog::current(&root).expect("current");
	delete(dir.path(), "alice", "Old").expect("delete");
	let (_, entries) =
		crate::imap::changelog::since(&root, before.epoch, before.current).expect("since");
	let changes: Vec<Change> = entries.into_iter().map(|e| e.change).collect();
	assert_eq!(
		changes,
		vec![
			Change::email(crate::imap::changelog::Op::Destroyed, id),
			Change::mailbox(crate::imap::changelog::Op::Destroyed, "Old"),
		]
	);
}
