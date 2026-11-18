//! A delay holds delivery of everything, local recipients included, and
//! only for the mail an account submits.

use super::harness::*;
use crate::smtp::sink::{MessageSink, Submission};

const ON: &str = "[queue.undo_send]\ndelay_secs = 60\n";

#[test]
fn a_delay_holds_local_and_remote_recipients_until_its_time() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org", "carol@remote.example"]);
	assert!(release_at > 0, "the submission was not held");
	// Nothing was delivered or queued at submission.
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 0);
	assert!(spool_ids(rig.dir.path()).is_empty());
	// One second before its time, still nothing.
	let early = rig.releaser.release_due(release_at - 1).expect("pass");
	assert_eq!(early.released, 0);
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 0);
	assert!(spool_ids(rig.dir.path()).is_empty());
	// At its time both go, the remote part under the id the sender holds.
	let due = rig.releaser.release_due(release_at).expect("pass");
	assert_eq!(due.released, 1);
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 1);
	assert_eq!(spool_ids(rig.dir.path()), vec![id]);
	assert!(rig.store.lookup(id).expect("lookup").is_none());
}

#[test]
fn nothing_sleeps_the_delay_is_a_time_on_the_held_file() {
	let rig = rig(ON);
	let (_, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	let now = crate::storage::delivery_log::now_epoch();
	// The release time is the delay after the acceptance, read back from disk.
	assert!(
		(now..=now + 61).contains(&release_at) && release_at >= now + 59,
		"the release time must be about a minute after the acceptance"
	);
}

#[test]
fn mail_from_elsewhere_and_server_reports_are_never_held() {
	let rig = rig(ON);
	rig.sink
		.deliver(message(&["bob@example.org"]))
		.expect("deliver");
	rig.sink
		.deliver_report(message(&["bob@example.org"]))
		.expect("report");
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 2);
	assert!(rig.store.pending().expect("pending").is_empty());
}

#[test]
fn mail_whose_evidence_is_mandatory_is_not_held() {
	let rig = rig(ON);
	let result = rig.sink.submit(
		message(&["bob@example.org"]),
		uuid::Uuid::now_v7(),
		"alice",
		&Submission::of_class(crate::evidence::MailClass::Transactional),
	);
	// It went to the routing sink, which refuses it for want of evidence,
	// instead of waiting on disk.
	assert!(result.is_err());
	assert!(rig.store.pending().expect("pending").is_empty());
}

#[test]
fn a_delay_of_zero_changes_nothing() {
	for section in ["", "[queue.undo_send]\ndelay_secs = 0\n"] {
		let rig = rig(section);
		let (id, release_at) = submit(&rig, "alice", &["bob@example.org", "carol@remote.example"]);
		assert_eq!(release_at, 0, "nothing may be held");
		assert_eq!(inbox_count(rig.dir.path(), "bob"), 1);
		assert_eq!(spool_ids(rig.dir.path()), vec![id]);
		assert!(rig.store.pending().expect("pending").is_empty());
	}
}

#[test]
fn a_held_message_is_sealed_on_disk_when_storage_is_encrypted() {
	let crypto = crate::storage::MessageCrypto::for_test(&[7u8; 32]);
	let rig = rig_with(ON, crypto.clone());
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	let held = std::fs::read_dir(rig.dir.path().join("undo").join("pending"))
		.expect("dir")
		.flatten()
		.next()
		.expect("a held file");
	let bytes = std::fs::read(held.path()).expect("read");
	assert!(
		!String::from_utf8_lossy(&bytes).contains("the secret body"),
		"the body is on disk in the clear"
	);
	// It opens again, and goes out intact.
	rig.releaser.release_due(release_at).expect("pass");
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 1);
	assert!(rig.store.lookup(id).expect("lookup").is_none());
}
