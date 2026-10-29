//! Tests for the drain itself.

use std::time::Duration;

use super::{Drain, or_drain};

#[tokio::test]
async fn a_waiter_wakes_when_the_drain_starts_and_later_ones_at_once() {
	let drain = Drain::new();
	let waiter = {
		let drain = drain.clone();
		tokio::spawn(async move { drain.started().await })
	};
	tokio::task::yield_now().await;
	assert!(!waiter.is_finished());
	drain.begin();
	tokio::time::timeout(Duration::from_secs(1), waiter)
		.await
		.expect("woken")
		.unwrap();
	tokio::time::timeout(Duration::from_secs(1), drain.started())
		.await
		.expect("already started");
}

#[tokio::test]
async fn finished_waits_for_every_tracked_connection_up_to_the_deadline() {
	let drain = Drain::new();
	let first = drain.track();
	let second = drain.track();
	drain.begin();
	assert_eq!(drain.finished(Duration::from_millis(20)).await, 2);
	drop(first);
	let closing = tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(20)).await;
		drop(second);
	});
	assert_eq!(drain.finished(Duration::from_secs(5)).await, 0);
	closing.await.unwrap();
}

#[tokio::test]
async fn a_read_gives_way_to_the_drain() {
	let drain = Drain::new();
	drain.begin();
	let pending = std::future::pending::<()>();
	assert!(
		or_drain(Some(&drain), Duration::from_secs(5), pending)
			.await
			.is_none()
	);
	let ready = std::future::ready(7);
	assert_eq!(
		or_drain(None, Duration::from_secs(5), ready)
			.await
			.map(Result::ok),
		Some(Some(7))
	);
}
