//! A destination that asks the queue to slow down is held off as a whole,
//! for longer each time it does so in a row, and released by the first
//! conversation that delivers once the hold has run out. A `452 4.5.3` only sends the extra
//! recipients to another transaction at once.

use super::*;
use crate::queue::backoff::{Hold, Holds};
use crate::queue::destination::Destination;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::storage::{DeliveryLog, DeliveryOutcome, RecipientStatus};

const DOMAIN: &str = "busy.example";
const HOST: &str = "mx.busy.example";

pub(in super::super) fn store(spool: &FsSpool, recipients: &[&str]) {
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: recipients.iter().map(|r| r.to_string()).collect(),
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
				sender_verified: false,
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
}

/// A worker over a spool with one message to `recipients`, delivering
/// through `remote`, its clock at the message's creation plus a second,
/// and with no spread on retry waits.
pub(in super::super) fn worker_for(
	dir: &std::path::Path,
	recipients: &[&str],
	remote: &FakeRemote,
) -> (Worker, u64) {
	let spool = FsSpool::open(dir).expect("open spool");
	store(&spool, recipients);
	let created = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	let mut worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	worker.set_jitter(|| 1.0);
	worker.set_now(created + 1);
	(worker, created + 1)
}

/// The hold of `key` at `now`, as the spool shows it.
pub(in super::super) fn hold(worker: &Worker, key: &Destination, now: u64) -> Option<Hold> {
	Holds::read(&worker.spool)
		.expect("holds")
		.held(key, now)
		.cloned()
}

pub(in super::super) fn greeting(reply: &str) -> Script {
	Script {
		greeting: Some(reply.to_string()),
		..Script::default()
	}
}

#[tokio::test]
async fn a_421_greeting_holds_the_destination_and_its_other_mail_waits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);

	worker.pass().await.expect("pass");

	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN), now),
		Some(Hold {
			until: now + 60,
			deferrals: 1,
			reason: "421 4.7.0 slow down".into(),
		}),
		"the destination is on hold"
	);
	assert_eq!(
		hold(&worker, &Destination::exchanger(HOST), now).map(|hold| hold.until),
		Some(now + 60)
	);

	// Mail for the held destination waits, without an attempt counted.
	store(&worker.spool, &["carol@busy.example"]);
	worker.set_now(now + 30);
	worker.pass().await.expect("pass");
	assert_eq!(remote.connections(HOST), 1, "nothing tried while on hold");
	let carol = worker
		.spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| worker.spool.load_envelope(id).expect("envelope"))
		.find(|envelope| envelope.recipients == ["carol@busy.example"])
		.expect("carol's message");
	let state = carol.recipient_state("carol@busy.example");
	assert_eq!(
		(state.status, state.attempts),
		(RecipientStatus::Pending, 0)
	);
}

#[tokio::test]
async fn deferring_again_after_the_hold_moves_to_the_next_step_and_success_resets() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");

	worker.set_now(now + 60);
	worker.pass().await.expect("pass");
	let held = hold(&worker, &Destination::domain(DOMAIN), now + 60).expect("held");
	assert_eq!((held.until, held.deferrals), (now + 360, 2));

	worker.set_now(now + 360);
	worker.pass().await.expect("pass");
	let held = hold(&worker, &Destination::domain(DOMAIN), now + 360).expect("held");
	assert_eq!((held.until, held.deferrals), (now + 1260, 3));

	remote.script(DOMAIN, Script::default());
	worker.set_now(now + 1260);
	worker.pass().await.expect("pass");
	assert_eq!(remote.copies("bob@busy.example"), 1);
	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN), now),
		None,
		"a delivery ends the hold"
	);
	assert_eq!(remote.connections(HOST), 4);
}

#[tokio::test]
async fn a_rate_limit_reply_to_rcpt_holds_the_destination() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(
		DOMAIN,
		Script::rcpt("bob@busy.example", "450 4.7.1 too many connections"),
	);
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN), now).map(|hold| hold.until),
		Some(now + 60)
	);
}

#[tokio::test]
async fn a_rate_limit_reply_to_the_message_holds_the_destination() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(
		DOMAIN,
		Script {
			data: Some("451 4.7.650 temporarily rate limited".into()),
			..Script::default()
		},
	);
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN), now).map(|hold| hold.until),
		Some(now + 60)
	);
}

#[tokio::test]
async fn an_ordinary_deferral_does_not_hold_the_destination() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(
		DOMAIN,
		Script::rcpt("bob@busy.example", "450 4.2.0 mailbox busy"),
	);
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(hold(&worker, &Destination::domain(DOMAIN), now), None);
}

#[tokio::test]
async fn the_steps_are_configurable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 busy"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	let worker = worker.with_backoff(vec![120, 600]);
	worker.pass().await.expect("pass");
	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN), now).map(|hold| hold.until),
		Some(now + 120)
	);
}

#[tokio::test]
async fn a_hold_survives_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	worker.pass().await.expect("pass");
	drop(worker);

	remote.script(DOMAIN, Script::default());
	let mut restarted = Worker::new(
		FsSpool::open(dir.path()).expect("reopen"),
		Arc::new(remote.clone()),
		"mail.sender.example",
	);
	restarted.set_jitter(|| 1.0);
	restarted.set_now(now + 30);
	store(&restarted.spool, &["carol@busy.example"]);
	restarted.pass().await.expect("pass");
	assert_eq!(
		remote.connections(HOST),
		1,
		"still on hold after the restart"
	);

	// The hold ends: the next pass goes ahead.
	restarted.set_now(now + 60);
	restarted.pass().await.expect("pass");
	assert_eq!(remote.copies("carol@busy.example"), 1);
}

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
