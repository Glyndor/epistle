//! A provider that hosts many domains on the same exchangers sets its rate
//! limit on those exchangers: once one of its hosts asks to slow down, no
//! domain it serves gets a fresh conversation with it until the hold ends,
//! and a conversation that was already under way and delivered does not
//! lift a hold still in force.

use super::tests_backoff::{greeting, hold, store, worker_for};
use super::*;
use crate::queue::destination::Destination;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::storage::RecipientStatus;

const PROVIDER: &str = "mx.provider.example";

fn recipient_state(worker: &Worker, recipient: &str) -> crate::storage::RecipientState {
	let id = worker
		.spool
		.list()
		.expect("list")
		.into_iter()
		.find(|id| {
			worker
				.spool
				.load_envelope(*id)
				.is_ok_and(|envelope| envelope.recipients.iter().any(|r| r == recipient))
		})
		.expect("entry");
	worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state(recipient)
}

#[tokio::test]
async fn another_domain_on_a_held_exchanger_waits_for_the_hold() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("a.example", PROVIDER, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["alice@a.example"], &remote);

	worker.pass().await.expect("pass");

	let until = hold(&worker, &Destination::exchanger(PROVIDER), now)
		.expect("the exchanger is held")
		.until;
	assert_eq!(until, now + 60);
	assert!(hold(&worker, &Destination::domain("a.example"), now).is_some());

	// The provider would take mail for b.example, but it asked to slow down.
	remote.hosted("b.example", PROVIDER, Script::default());
	store(&worker.spool, &["bob@b.example"]);
	worker.set_now(now + 30);
	worker.pass().await.expect("pass");

	assert!(remote.received().is_empty(), "{:?}", remote.received());
	let bob = recipient_state(&worker, "bob@b.example");
	assert_eq!(
		(bob.status, bob.attempts, bob.next_attempt),
		(RecipientStatus::Pending, 0, until),
		"no attempt counted, due when the hold ends"
	);
	assert_eq!(
		bob.last_error.as_deref(),
		Some("mx.provider.example is on hold: 421 4.7.0 slow down")
	);

	// Once the hold has run out, and the provider takes mail again, both
	// go through, and the deliveries end the holds.
	remote.hosted("a.example", PROVIDER, Script::default());
	worker.set_now(until);
	worker.pass().await.expect("pass");
	assert_eq!(remote.copies("bob@b.example"), 1);
	assert_eq!(remote.copies("alice@a.example"), 1);
	assert!(worker.spool.list().expect("list").is_empty());
	assert_eq!(hold(&worker, &Destination::exchanger(PROVIDER), now), None);
}
