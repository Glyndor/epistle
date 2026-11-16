//! The releaser against a sink that refuses.

use std::sync::{Arc, Mutex};

use super::harness::*;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError, Submission};
use crate::storage::undo::{Releaser, UndoPolicy, UndoSink, UndoStore};

/// A sink whose `submit` fails as told and which keeps the reports it gets.
struct Stub {
	refuse: Mutex<Option<fn() -> SinkError>>,
	submitted: Mutex<Vec<uuid::Uuid>>,
	reports: Mutex<Vec<AcceptedMessage>>,
}

impl MessageSink for Stub {
	fn deliver(&self, _: AcceptedMessage) -> Result<(), SinkError> {
		Ok(())
	}

	fn deliver_report(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.reports.lock().expect("lock").push(message);
		Ok(())
	}

	fn submit(
		&self,
		_: AcceptedMessage,
		queue_id: uuid::Uuid,
		_: &str,
		_: &Submission,
	) -> Result<(), SinkError> {
		if let Some(refuse) = *self.refuse.lock().expect("lock") {
			return Err(refuse());
		}
		self.submitted.lock().expect("lock").push(queue_id);
		Ok(())
	}
}

fn stubbed(
	refuse: Option<fn() -> SinkError>,
) -> (
	Arc<Stub>,
	Arc<UndoStore>,
	Releaser,
	UndoSink,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	let stub = Arc::new(Stub {
		refuse: Mutex::new(refuse),
		submitted: Mutex::new(Vec::new()),
		reports: Mutex::new(Vec::new()),
	});
	let store = Arc::new(
		UndoStore::open(dir.path(), crate::storage::MessageCrypto::disabled()).expect("store"),
	);
	let policy = UndoPolicy::from_config(&config("[queue.undo_send]\ndelay_secs = 60\n"));
	let sink = UndoSink::new(stub.clone(), store.clone(), policy, directory());
	let releaser = Releaser::new(store.clone(), stub.clone(), style());
	(stub, store, releaser, sink, dir)
}

fn hold(sink: &UndoSink, store: &UndoStore) -> (uuid::Uuid, u64) {
	let id = uuid::Uuid::now_v7();
	sink.submit(
		message(&["bob@example.org"]),
		id,
		"alice",
		&Submission::default(),
	)
	.expect("submit");
	(id, store.lookup(id).expect("lookup").expect("held").1)
}

#[test]
fn a_refusal_that_will_come_again_tells_the_sender_and_ends_the_hold() {
	let (stub, store, releaser, sink, _dir) =
		stubbed(Some(|| SinkError::MailboxFull("bob".into())));
	let (id, release_at) = hold(&sink, &store);
	let pass = releaser.release_due(release_at).expect("pass");
	assert_eq!((pass.released, pass.refused, pass.waiting), (0, 1, 0));
	assert!(store.lookup(id).expect("lookup").is_none());
	let reports = stub.reports.lock().expect("lock");
	assert_eq!(reports.len(), 1, "the sender must be told");
	assert_eq!(reports[0].recipients, vec!["alice@example.org".to_string()]);
}

#[test]
fn a_transient_refusal_keeps_it_and_the_next_pass_hands_it_on() {
	let (stub, store, releaser, sink, _dir) =
		stubbed(Some(|| SinkError::Unavailable("disk".into())));
	let (id, release_at) = hold(&sink, &store);
	let pass = releaser.release_due(release_at).expect("pass");
	assert_eq!((pass.released, pass.refused, pass.waiting), (0, 0, 1));
	assert!(store.lookup(id).expect("lookup").is_some(), "must be kept");
	assert!(stub.reports.lock().expect("lock").is_empty());
	*stub.refuse.lock().expect("lock") = None;
	let pass = releaser.release_due(release_at + 2).expect("pass");
	assert_eq!(pass.released, 1);
	assert_eq!(*stub.submitted.lock().expect("lock"), vec![id]);
}

#[test]
fn a_transient_refusal_is_given_up_after_a_day() {
	let (stub, store, releaser, sink, _dir) =
		stubbed(Some(|| SinkError::Unavailable("disk".into())));
	let (id, release_at) = hold(&sink, &store);
	let day = 86_400;
	assert_eq!(
		releaser
			.release_due(release_at + day)
			.expect("pass")
			.waiting,
		1
	);
	let pass = releaser.release_due(release_at + day + 1).expect("pass");
	assert_eq!(pass.refused, 1);
	assert!(store.lookup(id).expect("lookup").is_none());
	assert_eq!(stub.reports.lock().expect("lock").len(), 1);
}
