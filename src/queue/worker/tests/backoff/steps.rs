//! Backoff tests for the 452 recipient split and for repeated holds.

use super::*;

#[tokio::test]
async fn the_extra_recipients_of_a_452_go_out_at_once_and_are_not_failures() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(
		DOMAIN,
		Script {
			max_recipients: Some(2),
			..Script::default()
		},
	);
	let recipients = [
		"a@busy.example",
		"b@busy.example",
		"c@busy.example",
		"d@busy.example",
		"e@busy.example",
	];
	let (worker, _) = worker_for(dir.path(), &recipients, &remote);
	let worker = worker.with_delivery_log(DeliveryLog::open(dir.path(), 30));

	assert_eq!(worker.pass().await.expect("pass"), 1);

	let batches: Vec<usize> = remote
		.received()
		.iter()
		.map(|message| message.recipients.len())
		.collect();
	assert_eq!(batches, [2, 2, 1]);
	for recipient in recipients {
		assert_eq!(remote.copies(recipient), 1, "{recipient}");
	}
	assert!(worker.spool.list().expect("list").is_empty());
	let log = DeliveryLog::open(dir.path(), 30)
		.list(None, |_| true)
		.expect("log");
	assert_eq!(log.len(), 5);
	assert!(
		log.iter()
			.all(|record| record.outcome == DeliveryOutcome::Delivered && record.attempt == 1),
		"{log:?}"
	);
}

#[tokio::test]
async fn a_452_that_takes_no_recipient_is_an_ordinary_deferral() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(
		DOMAIN,
		Script {
			max_recipients: Some(0),
			..Script::default()
		},
	);
	let (worker, _) = worker_for(dir.path(), &["a@busy.example", "b@busy.example"], &remote);
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(remote.connections(HOST), 1, "no retry loop");
	let id = worker.spool.list().expect("list")[0];
	let envelope = worker.spool.load_envelope(id).expect("envelope");
	for recipient in ["a@busy.example", "b@busy.example"] {
		let state = envelope.recipient_state(recipient);
		assert_eq!(state.attempts, 1, "{recipient}");
		assert_eq!(
			state.last_error.as_deref(),
			Some("452 4.5.3 too many recipients")
		);
	}
}

#[tokio::test]
async fn a_hold_lasts_the_backoff_step_whatever_the_retry_schedule_of_its_recipient() {
	// A recipient deferred many times before (its next retry an hour off)
	// meets a rate limit: the whole destination is held for the backoff
	// step, not for that one recipient's hour.
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	let id = worker.spool.list().expect("list")[0];
	worker
		.spool
		.update_envelope(id, |envelope| {
			let mut state = envelope.recipient_state("bob@busy.example");
			state.attempts = 6;
			envelope.set_recipient_state("bob@busy.example", state);
		})
		.expect("update");

	worker.pass().await.expect("pass");

	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN), now).map(|hold| hold.until),
		Some(now + 60)
	);
	assert_eq!(
		hold(&worker, &Destination::exchanger(HOST), now).map(|hold| hold.until),
		Some(now + 60)
	);
}

#[tokio::test]
async fn a_released_destination_that_asks_again_is_held_again() {
	// An operator's release lifts one hold; it cannot make the queue
	// ignore the remote: the next slow-down reply holds it once more.
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	// What `epistle queue release-destination` writes.
	let id = worker.spool.list().expect("list")[0];
	worker
		.spool
		.update_envelope(id, |envelope| {
			let mut state = envelope.recipient_state("bob@busy.example");
			state.throttled = 0;
			state.next_attempt = now;
			envelope.set_recipient_state("bob@busy.example", state);
			envelope.settle();
		})
		.expect("release");
	assert_eq!(hold(&worker, &Destination::domain(DOMAIN), now), None);

	worker.pass().await.expect("pass");
	worker.pass().await.expect("pass");

	assert_eq!(
		remote.connections(HOST),
		2,
		"contacted once after the release"
	);
	let held = hold(&worker, &Destination::domain(DOMAIN), now).expect("held again");
	assert_eq!((held.until, held.deferrals), (now + 60, 1));
}
