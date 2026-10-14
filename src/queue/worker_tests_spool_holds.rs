//! The holds live in the spool and nowhere else: the worker's own copy can
//! be dropped at any time, by a restart or otherwise, and the next scan
//! reads the same holds back, for the domain and for the exchanger.

use super::tests_backoff::{greeting, hold, store, worker_for};
use super::*;
use crate::queue::test_remote::{FakeRemote, Script};

const PROVIDER: &str = "mx.provider.example";

#[tokio::test]
async fn a_dropped_copy_of_the_holds_is_read_back_from_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script("busy.example", greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	assert!(hold(&worker, "busy.example", now).is_some());

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
