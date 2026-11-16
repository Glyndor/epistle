//! The claim: a release and a cancel cannot both win, two releasers cannot
//! both send, and a claim left by a dead process is retried. The sink blocks
//! on channels, never on time, so each order is forced.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use super::harness::{config, directory, message, style};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError, Submission};
use crate::storage::undo::{CancelError, Canceller, Releaser, UndoPolicy, UndoSink, UndoStore};

/// Counts what it is handed, and can stop inside `submit` until told.
struct Gate {
	sent: Mutex<Vec<uuid::Uuid>>,
	inside: Mutex<Option<Sender<()>>>,
	proceed: Mutex<Option<Receiver<()>>>,
}

impl MessageSink for Gate {
	fn deliver(&self, _: AcceptedMessage) -> Result<(), SinkError> {
		Ok(())
	}

	fn submit(
		&self,
		_: AcceptedMessage,
		id: uuid::Uuid,
		_: &str,
		_: &Submission,
	) -> Result<(), SinkError> {
		if let Some(inside) = self.inside.lock().expect("lock").take() {
			inside.send(()).expect("signal");
			let proceed = self.proceed.lock().expect("lock").take().expect("proceed");
			proceed.recv().expect("proceed");
		}
		self.sent.lock().expect("lock").push(id);
		Ok(())
	}
}

struct Rig {
	gate: Arc<Gate>,
	store: Arc<UndoStore>,
	releaser: Arc<Releaser>,
	id: uuid::Uuid,
	release_at: u64,
	_dir: tempfile::TempDir,
}

fn rig() -> Rig {
	let dir = tempfile::tempdir().expect("tempdir");
	let gate = Arc::new(Gate {
		sent: Mutex::new(Vec::new()),
		inside: Mutex::new(None),
		proceed: Mutex::new(None),
	});
	let store = Arc::new(
		UndoStore::open(dir.path(), crate::storage::MessageCrypto::disabled()).expect("store"),
	);
	let policy = UndoPolicy::from_config(&config("[queue.undo_send]\ndelay_secs = 60\n"));
	let sink = UndoSink::new(gate.clone(), store.clone(), policy, directory());
	let id = uuid::Uuid::now_v7();
	sink.submit(
		message(&["bob@example.org"]),
		id,
		"alice",
		&Submission::default(),
	)
	.expect("submit");
	let release_at = store.lookup(id).expect("lookup").expect("held").1;
	let releaser = Arc::new(Releaser::new(store.clone(), gate.clone(), style()));
	Rig {
		gate,
		store,
		releaser,
		id,
		release_at,
		_dir: dir,
	}
}

/// Start a release that stops inside the sink; returns once it is there.
fn release_stopped_in_sink(rig: &Rig, now: u64) -> (std::thread::JoinHandle<()>, Sender<()>) {
	let (inside_tx, inside_rx) = channel();
	let (go_tx, go_rx) = channel();
	*rig.gate.inside.lock().expect("lock") = Some(inside_tx);
	*rig.gate.proceed.lock().expect("lock") = Some(go_rx);
	let releaser = rig.releaser.clone();
	let handle = std::thread::spawn(move || {
		releaser.release_due(now).expect("pass");
	});
	inside_rx.recv().expect("the release reached the sink");
	(handle, go_tx)
}

#[test]
fn a_cancel_while_the_message_is_in_the_sink_is_already_sent_and_it_goes_once() {
	let rig = rig();
	let (handle, go) = release_stopped_in_sink(&rig, rig.release_at);
	// Even a cancel whose clock still reads before the release time loses:
	// the message was claimed under the lock.
	let early = rig
		.store
		.cancel(rig.id, Canceller::Account("alice"), rig.release_at - 30)
		.expect_err("must refuse");
	assert!(matches!(early, CancelError::AlreadySent), "{early:?}");
	let other = rig
		.store
		.cancel(rig.id, Canceller::Account("bob"), rig.release_at - 30)
		.expect_err("must refuse");
	assert!(matches!(other, CancelError::NotFound), "{other:?}");
	go.send(()).expect("go");
	handle.join().expect("release");
	assert_eq!(*rig.gate.sent.lock().expect("lock"), vec![rig.id]);
}

#[test]
fn a_cancel_that_wins_first_means_the_release_sends_nothing() {
	let rig = rig();
	rig.store
		.cancel(rig.id, Canceller::Account("alice"), rig.release_at - 1)
		.expect("cancel");
	let pending = rig.store.due(rig.release_at).expect("due");
	assert!(pending.is_empty());
	// A releaser that had listed it before the cancel finds nothing to claim.
	let stale = crate::storage::undo::Pending {
		id: rig.id,
		release_at: rig.release_at,
	};
	assert!(rig.store.claim(&stale).expect("claim").is_none());
	rig.releaser.release_due(rig.release_at).expect("pass");
	assert!(rig.gate.sent.lock().expect("lock").is_empty());
}

#[test]
fn two_releasers_send_a_message_once() {
	let rig = rig();
	let (handle, go) = release_stopped_in_sink(&rig, rig.release_at);
	// A second pass while the first is inside the sink finds it claimed.
	let second = rig.releaser.release_due(rig.release_at).expect("pass");
	assert_eq!(second.released, 0);
	go.send(()).expect("go");
	handle.join().expect("release");
	assert_eq!(*rig.gate.sent.lock().expect("lock"), vec![rig.id]);
}

#[test]
fn a_claim_left_by_a_dead_process_is_retried_at_the_next_start() {
	let rig = rig();
	let due = rig.store.due(rig.release_at).expect("due");
	let held = rig.store.claim(&due[0]).expect("claim").expect("held");
	assert_eq!(held.id, rig.id);
	// The process dies here: nothing was sent and nothing is pending.
	assert!(rig.store.due(rig.release_at).expect("due").is_empty());
	assert!(rig.gate.sent.lock().expect("lock").is_empty());
	// A cancel meanwhile is refused: it is being handed on.
	let refused = rig
		.store
		.cancel(rig.id, Canceller::Account("alice"), 0)
		.expect_err("must refuse");
	assert!(matches!(refused, CancelError::AlreadySent), "{refused:?}");
	// The next start puts it back and sends it, once.
	let restarted = Releaser::new(rig.store.clone(), rig.gate.clone(), style());
	assert_eq!(
		restarted
			.release_due(rig.release_at)
			.expect("pass")
			.released,
		1
	);
	assert_eq!(*rig.gate.sent.lock().expect("lock"), vec![rig.id]);
}
