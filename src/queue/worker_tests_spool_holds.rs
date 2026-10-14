//! The holds live in the spool and nowhere else: the worker's own copy can
//! be dropped at any time, by a restart or otherwise, and the next scan
//! reads the same holds back, for the domain and for the exchanger.

use super::tests_backoff::{greeting, hold, store, worker_for};
use super::*;
use crate::queue::destination::Destination;
use crate::queue::test_remote::{FakeRemote, Script};

const PROVIDER: &str = "mx.provider.example";

#[tokio::test]
async fn a_dropped_copy_of_the_holds_is_read_back_from_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script("busy.example", greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	assert!(hold(&worker, &Destination::domain("busy.example"), now).is_some());

	*worker.holds() = crate::queue::backoff::Holds::default();
	remote.script("busy.example", Script::default());
	store(&worker.spool, &["carol@busy.example"]);
	worker.set_now(now + 30);
	worker.pass().await.expect("pass");

	assert_eq!(remote.connections("mx.busy.example"), 1, "still on hold");
	assert_eq!(remote.copies("carol@busy.example"), 0);
}

#[tokio::test]
async fn a_restarted_worker_keeps_an_exchanger_on_hold_for_other_domains() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("a.example", PROVIDER, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["alice@a.example"], &remote);
	worker.pass().await.expect("pass");
	drop(worker);

	remote.hosted("b.example", PROVIDER, Script::default());
	let mut restarted = Worker::new(
		FsSpool::open(dir.path()).expect("reopen"),
		Arc::new(remote.clone()),
		"mail.sender.example",
	);
	restarted.set_jitter(|| 1.0);
	restarted.set_now(now + 30);
	store(&restarted.spool, &["bob@b.example"]);
	restarted.pass().await.expect("pass");

	assert!(remote.received().is_empty(), "{:?}", remote.received());
}

#[tokio::test]
async fn an_exchanger_on_hold_is_not_even_connected_to_for_another_domain() {
	// The provider asked to slow down: a message to another of its domains
	// must not open a connection to it only to drop it unspoken, which is
	// the very load it asked to shed.
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("a.example", PROVIDER, greeting("421 4.7.0 slow down"));
	remote.hosted("b.example", PROVIDER, Script::default());
	let (worker, now) = worker_for(dir.path(), &["alice@a.example"], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(remote.connections(PROVIDER), 1);

	store(&worker.spool, &["bob@b.example"]);
	worker.set_now(now + 30);
	worker.pass().await.expect("pass");

	assert_eq!(
		remote.connections(PROVIDER),
		1,
		"no connection while on hold"
	);
	assert_eq!(remote.copies("bob@b.example"), 0);
	let bob = worker
		.spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| worker.spool.load_envelope(id).expect("envelope"))
		.find(|envelope| envelope.recipients == ["bob@b.example"])
		.expect("bob's message")
		.recipient_state("bob@b.example");
	assert_eq!(
		(bob.attempts, bob.next_attempt),
		(0, now + 60),
		"bob waits for the hold, no attempt counted"
	);
	assert_eq!(
		bob.remote.as_deref(),
		Some(PROVIDER),
		"the exchanger bob waits for, so releasing it frees him"
	);
}
