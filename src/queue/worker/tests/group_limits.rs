//! The limit of a receiver group is shared by every recipient domain the
//! provider hosts: the exchanger that answers names the group, not the
//! domain. Two groups never share, and a worker with no group limits runs
//! as it did before the setting existed. The clock is pinned and tokio's
//! paused clock runs the conversations.

use std::collections::BTreeMap;

use super::parallel::{slow, spool_each};
use super::*;
use crate::queue::limits::GroupLimit;
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::queue::warmup::Group;
use crate::storage::RecipientStatus;

const GOOGLE: &str = "mx.google.com";
const OUTLOOK: &str = "mx.outlook.com";

pub(super) fn limits<const N: usize>(
	entries: [(Group, GroupLimit); N],
) -> BTreeMap<Group, GroupLimit> {
	entries.into_iter().collect()
}

/// A worker over one message per recipient, with the clock pinned, and the
/// second after the messages were spooled.
fn worker_for(
	dir: &std::path::Path,
	recipients: &[&str],
	remote: &FakeRemote,
	limits: BTreeMap<Group, GroupLimit>,
) -> (Worker, u64) {
	let spool = spool_each(dir, recipients);
	let start = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7 timestamp")
		.to_unix()
		.0
		+ 1;
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_per_group_concurrency(limits);
	worker.set_now(start);
	(worker, start)
}

fn host_both(remote: &FakeRemote, host: &str) {
	for domain in ["one.example", "two.example"] {
		remote.hosted(domain, host, slow(10));
	}
}

#[tokio::test(start_paused = true)]
async fn two_domains_of_one_group_share_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	host_both(&remote, GOOGLE);
	let (worker, start) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([(Group::Gmail, GroupLimit::new(1))]),
	);

	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert_eq!(remote.most_at_once_total(), 1);
	assert_eq!(worker.spool.list().expect("list").len(), 1);

	worker.set_now(start + 2);
	assert_eq!(worker.pass().await.expect("second pass"), 1);
	assert_eq!(remote.most_at_once_total(), 1, "never two at once");
	assert_eq!(
		remote.copies("a@one.example") + remote.copies("b@two.example"),
		2
	);
	assert!(worker.spool.list().expect("list").is_empty());
}

#[tokio::test(start_paused = true)]
async fn two_groups_do_not_share_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("one.example", GOOGLE, slow(10));
	remote.hosted("two.example", OUTLOOK, slow(10));
	let (worker, _) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([
			(Group::Gmail, GroupLimit::new(1)),
			(Group::Outlook, GroupLimit::new(1)),
		]),
	);

	assert_eq!(worker.pass().await.expect("pass"), 2);

	assert_eq!(remote.most_at_once_total(), 2);
}

#[tokio::test(start_paused = true)]
async fn without_the_setting_nothing_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	host_both(&remote, GOOGLE);
	let (worker, _) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		BTreeMap::new(),
	);

	assert_eq!(worker.pass().await.expect("pass"), 2);

	assert_eq!(remote.most_at_once_total(), 2);
	assert!(worker.spool.list().expect("list").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_group_without_an_entry_is_not_limited() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	host_both(&remote, OUTLOOK);
	let (worker, _) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([(Group::Gmail, GroupLimit::new(1))]),
	);

	assert_eq!(worker.pass().await.expect("pass"), 2);

	assert_eq!(remote.most_at_once_total(), 2);
}

#[tokio::test(start_paused = true)]
async fn unrelated_receivers_never_share_a_group() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("one.example", "mx.alpha.example", slow(10));
	remote.hosted("two.example", "mx.beta.example", slow(10));
	let (worker, _) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([(Group::Other, GroupLimit::new(1))]),
	);

	assert_eq!(worker.pass().await.expect("pass"), 2);

	assert_eq!(remote.most_at_once_total(), 2, "`other` is not one queue");
}

#[tokio::test(start_paused = true)]
async fn the_group_waits_between_two_of_its_connections() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	host_both(&remote, GOOGLE);
	let wait = GroupLimit {
		concurrency: 1,
		min_wait_secs: 60,
	};
	let (worker, start) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([(Group::Gmail, wait)]),
	);
	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert_eq!(remote.connections(GOOGLE), 1);

	worker.set_now(start + 30);
	assert_eq!(worker.pass().await.expect("inside the wait"), 0);
	assert_eq!(
		remote.connections(GOOGLE),
		1,
		"no connection before the wait"
	);

	worker.set_now(start + 61);
	assert_eq!(worker.pass().await.expect("after the wait"), 1);
	assert_eq!(remote.connections(GOOGLE), 2);
	assert!(worker.spool.list().expect("list").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_recipient_waiting_for_a_group_slot_counts_no_attempt() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	host_both(&remote, GOOGLE);
	let (worker, start) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([(Group::Gmail, GroupLimit::new(1))]),
	);

	assert_eq!(worker.pass().await.expect("pass"), 1);

	let left = worker.spool.list().expect("list");
	let envelope = worker.spool.load_envelope(left[0]).expect("envelope");
	let waiting = ["a@one.example", "b@two.example"]
		.into_iter()
		.find(|recipient| remote.copies(recipient) == 0)
		.expect("one recipient is still waiting");
	let state = envelope.recipient_state(waiting);
	assert_eq!(state.status, RecipientStatus::Pending);
	assert_eq!(state.attempts, 0, "waiting for a slot is not an attempt");
	assert_eq!(state.next_attempt, start + 1);
	let error = state.last_error.expect("the reason it waits");
	assert!(error.contains("the gmail group is at its limit"), "{error}");
}

#[tokio::test(start_paused = true)]
async fn the_per_domain_limit_still_applies_inside_a_group() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("one.example", GOOGLE, slow(10));
	let (worker, _) = worker_for(
		dir.path(),
		&["a@one.example", "b@one.example", "c@one.example"],
		&remote,
		limits([(Group::Gmail, GroupLimit::new(4))]),
	);
	let worker = worker.with_concurrency(8, 1);

	assert_eq!(worker.pass().await.expect("pass"), 3);

	assert_eq!(remote.most_at_once("one.example"), 1);
}

#[tokio::test(start_paused = true)]
async fn a_failed_conversation_gives_its_slot_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted(
		"one.example",
		GOOGLE,
		Script::rcpt("a@one.example", "550 5.1.1 no such user"),
	);
	remote.hosted("two.example", GOOGLE, slow(1));
	let (worker, start) = worker_for(
		dir.path(),
		&["a@one.example", "b@two.example"],
		&remote,
		limits([(Group::Gmail, GroupLimit::new(1))]),
	);

	for step in 0..3 {
		worker.set_now(start + 2 * step);
		worker.pass().await.expect("pass");
	}

	assert_eq!(
		remote.copies("b@two.example"),
		1,
		"the group is not starved"
	);
	assert!(remote.most_at_once_total() <= 1);
}
