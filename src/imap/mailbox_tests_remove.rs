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
