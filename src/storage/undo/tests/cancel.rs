//! Cancelling: before the time it removes the message and nothing is sent;
//! after, or for anyone but the sender, it is refused, and says which.

use super::harness::*;
use crate::storage::undo::{CancelError, Canceller};

const ON: &str = "[queue.undo_send]\ndelay_secs = 60\n";

#[test]
fn cancel_before_the_time_removes_it_and_nothing_is_ever_sent() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org", "carol@remote.example"]);
	rig.store
		.cancel(id, Canceller::Account("alice"), release_at - 1)
		.expect("cancel");
	assert!(rig.store.lookup(id).expect("lookup").is_none());
	// Not even a release pass long after finds it.
	let pass = rig.releaser.release_due(release_at + 3600).expect("pass");
	assert_eq!(pass.released, 0);
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 0);
	assert!(spool_ids(rig.dir.path()).is_empty());
}

#[test]
fn cancel_at_the_release_time_is_already_sent() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	let error = rig
		.store
		.cancel(id, Canceller::Account("alice"), release_at)
		.expect_err("must refuse");
	assert!(matches!(error, CancelError::AlreadySent), "{error:?}");
	// The refusal did not remove it: it still goes out.
	rig.releaser.release_due(release_at).expect("pass");
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 1);
}

#[test]
fn cancel_after_delivery_is_already_sent_and_delivers_nothing_more() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org", "carol@remote.example"]);
	rig.releaser.release_due(release_at).expect("pass");
	let error = rig
		.store
		.cancel(id, Canceller::Account("alice"), release_at + 5)
		.expect_err("must refuse");
	assert!(matches!(error, CancelError::AlreadySent), "{error:?}");
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 1);
	assert_eq!(spool_ids(rig.dir.path()), vec![id]);
}

#[test]
fn another_account_cannot_cancel_and_learns_nothing() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	let other = rig
		.store
		.cancel(id, Canceller::Account("bob"), release_at - 10)
		.expect_err("must refuse");
	assert!(matches!(other, CancelError::NotFound), "{other:?}");
	// The same answer as an id nobody ever held.
	let unknown = rig
		.store
		.cancel(uuid::Uuid::now_v7(), Canceller::Account("bob"), 0)
		.expect_err("must refuse");
	assert!(matches!(unknown, CancelError::NotFound), "{unknown:?}");
	// It is still held, and the owner can still cancel it.
	assert!(rig.store.lookup(id).expect("lookup").is_some());
	rig.store
		.cancel(id, Canceller::Account("alice"), release_at - 10)
		.expect("owner cancels");
}

#[test]
fn another_account_is_not_told_that_a_message_was_already_sent() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	rig.releaser.release_due(release_at).expect("pass");
	let other = rig
		.store
		.cancel(id, Canceller::Account("bob"), release_at + 1)
		.expect_err("must refuse");
	assert!(matches!(other, CancelError::NotFound), "{other:?}");
}

#[test]
fn the_operator_can_cancel_any_held_message() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	rig.store
		.cancel(id, Canceller::Operator, release_at - 10)
		.expect("operator cancels");
	assert!(rig.store.lookup(id).expect("lookup").is_none());
}

#[test]
fn a_restart_keeps_the_hold_and_its_time() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	// A new process: a store and a releaser opened afresh on the same disk.
	let reopened = std::sync::Arc::new(
		crate::storage::undo::UndoStore::open(
			rig.dir.path(),
			crate::storage::MessageCrypto::disabled(),
		)
		.expect("reopen"),
	);
	assert_eq!(
		reopened.lookup(id).expect("lookup"),
		Some(("alice".to_string(), release_at))
	);
	let routing: std::sync::Arc<dyn crate::smtp::sink::MessageSink> = std::sync::Arc::new(
		crate::storage::SplitDelivery::new(rig.dir.path(), directory()).expect("routing"),
	);
	let releaser = crate::storage::undo::Releaser::new(reopened, routing, style());
	assert_eq!(
		releaser.release_due(release_at - 1).expect("pass").released,
		0
	);
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 0);
	assert_eq!(releaser.release_due(release_at).expect("pass").released, 1);
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 1);
}

#[test]
fn the_record_of_a_release_is_forgotten_after_a_day() {
	let rig = rig(ON);
	let (id, release_at) = submit(&rig, "alice", &["bob@example.org"]);
	rig.releaser.release_due(release_at).expect("pass");
	let almost = release_at + crate::storage::undo::RELEASED_KEPT_SECS;
	rig.releaser.release_due(almost).expect("pass");
	assert!(rig.store.released_account(id).expect("read").is_some());
	rig.releaser.release_due(almost + 1).expect("pass");
	assert!(rig.store.released_account(id).expect("read").is_none());
}
