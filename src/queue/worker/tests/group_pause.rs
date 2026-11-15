//! The group limit composes with the provider rate-limit pause: a throttled
//! group is held to one connection whatever `per_group_concurrency` allows,
//! and the group limit still applies when the pause is not in force. The
//! stricter of the two wins. The clock is tokio's paused clock.

use std::collections::BTreeMap;

use super::backoff::{greeting, store, worker_for};
use super::group_limits::limits;
use super::parallel::slow;
use super::*;
use crate::queue::limits::GroupLimit;
use crate::queue::tests::test_remote::FakeRemote;
use crate::queue::warmup::Group;

const BUSY: &str = "one.google.com";
const FRESH: [(&str, &str, &str); 3] = [
	("a.example", "mx-a.google.com", "a@a.example"),
	("b.example", "mx-b.google.com", "b@b.example"),
	("c.example", "mx-c.google.com", "c@c.example"),
];

/// A server that was rate limited by Gmail for `busy.example` and has been
/// restarted once the pause is over: its receiver group stays at one
/// connection while the rate-limited reply is pending in the spool.
async fn after_a_rate_limit(
	dir: &std::path::Path,
	remote: &FakeRemote,
	group_limits: BTreeMap<Group, GroupLimit>,
) -> (Worker, u64) {
	remote.hosted("busy.example", BUSY, greeting("421 4.7.28 anything"));
	let (worker, now) = worker_for(dir, &["bob@busy.example"], remote);
	worker.pass().await.expect("the rate limit");
	drop(worker);
	remote.hosted("busy.example", BUSY, slow(10));
	let worker = Worker::new(
		FsSpool::open(dir).expect("spool"),
		Arc::new(remote.clone()),
		"mail.sender.example",
	)
	.with_concurrency(8, 8)
	.with_per_group_concurrency(group_limits);
	worker.set_now(now + 600);
	(worker, now + 600)
}

/// Spool one fresh domain per recipient, all hosted by Gmail.
fn spool_fresh(worker: &Worker, remote: &FakeRemote) {
	for (domain, host, recipient) in FRESH {
		remote.hosted(domain, host, slow(10));
		store(&worker.spool, &[recipient]);
	}
}

/// The most connections open at once to Gmail, for a pause that is in
/// force or not and a group limit that is set or not.
async fn most_at_once(paused: bool, group: Option<usize>) -> usize {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let map = group.map_or_else(BTreeMap::new, |most| {
		limits([(Group::Gmail, GroupLimit::new(most))])
	});
	let worker = if paused {
		after_a_rate_limit(dir.path(), &remote, map).await.0
	} else {
		Worker::new(
			FsSpool::open(dir.path()).expect("spool"),
			Arc::new(remote.clone()),
			"mail.sender.example",
		)
		.with_concurrency(8, 8)
		.with_per_group_concurrency(map)
	};
	spool_fresh(&worker, &remote);
	worker.pass().await.expect("pass");
	remote.most_at_once_total()
}

#[tokio::test(start_paused = true)]
async fn a_paused_group_stays_at_one_connection_when_the_limit_allows_more() {
	assert_eq!(most_at_once(true, Some(4)).await, 1);
}

#[tokio::test(start_paused = true)]
async fn the_pause_and_the_group_limit_each_apply_in_all_four_combinations() {
	assert_eq!(most_at_once(false, None).await, 3, "neither");
	assert_eq!(
		most_at_once(false, Some(2)).await,
		2,
		"the group limit alone"
	);
	assert_eq!(most_at_once(true, None).await, 1, "the pause alone");
	assert_eq!(
		most_at_once(true, Some(2)).await,
		1,
		"both: the pause is stricter"
	);
}

#[tokio::test(start_paused = true)]
async fn the_group_wait_still_holds_once_the_pause_has_lifted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let wait = GroupLimit {
		concurrency: 4,
		min_wait_secs: 60,
	};
	let (worker, now) =
		after_a_rate_limit(dir.path(), &remote, limits([(Group::Gmail, wait)])).await;
	remote.hosted("a.example", FRESH[0].1, slow(10));
	store(&worker.spool, &[FRESH[0].2]);

	// The pause allows one connection, to the rate-limited domain's
	// recipient: it goes out, and the pause is over once it has.
	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert_eq!(
		remote.most_at_once_total(),
		1,
		"nothing beyond one while paused"
	);
	assert_eq!(remote.connections(FRESH[0].1), 0);

	// The pause no longer holds the group, but its minimum wait does.
	worker.set_now(now + 1);
	assert_eq!(worker.pass().await.expect("inside the wait"), 0);
	assert_eq!(remote.connections(FRESH[0].1), 0, "the wait is not over");

	worker.set_now(now + 61);
	assert_eq!(worker.pass().await.expect("after the wait"), 1);
	assert_eq!(remote.connections(FRESH[0].1), 1);
}
