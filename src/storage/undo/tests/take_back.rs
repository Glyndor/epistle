//! Taking back what an account holds when the account goes away: the pending
//! submissions of that account and no other are removed under the lock the
//! releaser claims under, so a removal that wins keeps them from ever being
//! handed on and one that loses does not claim to have taken back what is
//! already on its way.

use super::harness::*;
use crate::storage::undo::{TakenBack, UndoStore};

const ON: &str = "[queue.undo_send]\ndelay_secs = 60\n";

#[test]
fn what_an_account_held_is_not_delivered_after_it_is_taken_back() {
	let rig = rig(ON);
	let (_, due_at) = submit(&rig, "alice", &["carol@remote.example", "bob@example.org"]);
	let (bob_id, _) = submit(&rig, "bob", &["dave@remote.example"]);
	let taken = rig.store.take_back_account("alice").expect("take back");
	assert_eq!(
		taken,
		TakenBack {
			discarded: 1,
			claimed: 0
		}
	);
	let pass = rig.releaser.release_due(due_at + 120).expect("pass");
	assert_eq!(pass.released, 1, "only the other account's goes");
	assert_eq!(spool_ids(rig.dir.path()), vec![bob_id]);
	assert_eq!(inbox_count(rig.dir.path(), "bob"), 0, "nor the local copy");
}

#[test]
fn a_submission_already_claimed_is_not_counted_as_taken_back() {
	let rig = rig(ON);
	let (id, due_at) = submit(&rig, "alice", &["carol@remote.example"]);
	let pending = rig.store.due(due_at).expect("due").remove(0);
	let held = rig.store.claim(&pending).expect("claim").expect("claimed");
	assert_eq!(held.id, id);
	// The claim won: it is past recall, as it is for the sender's own cancel.
	let taken = rig.store.take_back_account("alice").expect("take back");
	assert_eq!(
		taken,
		TakenBack {
			discarded: 0,
			claimed: 1
		}
	);
	assert_eq!(rig.store.held_by("alice").expect("held"), 1);
}

#[test]
fn a_taken_back_submission_cannot_be_claimed() {
	let rig = rig(ON);
	let (_, due_at) = submit(&rig, "alice", &["carol@remote.example"]);
	let pending = rig.store.due(due_at).expect("due").remove(0);
	rig.store.take_back_account("alice").expect("take back");
	assert!(rig.store.claim(&pending).expect("claim").is_none());
}

#[test]
fn held_by_counts_one_account() {
	let rig = rig(ON);
	submit(&rig, "alice", &["carol@remote.example"]);
	submit(&rig, "alice", &["dave@remote.example"]);
	submit(&rig, "bob", &["carol@remote.example"]);
	assert_eq!(rig.store.held_by("alice").expect("held"), 2);
	assert_eq!(rig.store.held_by("bob").expect("held"), 1);
	assert_eq!(rig.store.held_by("nobody").expect("held"), 0);
}

#[test]
fn a_store_nothing_ever_created_stays_uncreated() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = crate::storage::MessageCrypto::disabled;
	assert!(
		UndoStore::open_existing(dir.path(), crypto())
			.expect("open")
			.is_none()
	);
	assert!(!dir.path().join("undo").exists());
	UndoStore::open(dir.path(), crypto()).expect("create");
	assert!(
		UndoStore::open_existing(dir.path(), crypto())
			.expect("open")
			.is_some()
	);
}
