//! Recipients over the warm-up cap of their receiver group wait in the
//! queue: not attempted, not failed, not logged as deferred, and not aging
//! toward the give-up window, then go out as the cap allows.

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::queue::warmup::settings::{self, Settings};
use crate::queue::warmup::{Group, Warmup};
use crate::queue::worker::tests_backoff::store;
use crate::storage::{DeliveryLog, DeliveryOutcome, FsSpool, RecipientStatus};

const GMAIL_MX: &str = "gmail-smtp-in.l.google.com";

/// A worker over `dir` with one message to `recipients`, delivering every
/// domain named through Gmail's exchanger, with the warm-up on.
fn capped_worker(
	dir: &std::path::Path,
	recipients: &[&str],
	remote: &FakeRemote,
) -> (Worker, u64, Arc<Warmup>) {
	for recipient in recipients {
		let domain = recipient
			.rsplit_once('@')
			.map(|(_, domain)| domain)
			.unwrap_or_default();
		remote.hosted(domain, GMAIL_MX, Script::default());
	}
	let spool = FsSpool::open(dir).expect("open spool");
	store(&spool, recipients);
	let created = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	let now = created + 1;
	settings::save(
		dir,
		&Settings {
			enabled: true,
			..Settings::default()
		},
	)
	.expect("settings");
	let log = DeliveryLog::open(dir, 30);
	let warmup = Arc::new(Warmup::open(dir, Some(log.clone()), now));
	let mut worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_delivery_log(log)
		.with_warmup(Arc::clone(&warmup));
	worker.set_jitter(|| 1.0);
	worker.set_now(now);
	(worker, now, warmup)
}

fn states(worker: &Worker) -> Vec<(String, RecipientStatus, u32, Option<String>, u64)> {
	let id = worker.spool.list().expect("list")[0];
	let envelope = worker.spool.load_envelope(id).expect("envelope");
	envelope
		.recipients
		.iter()
		.map(|recipient| {
			let state = envelope.recipient_state(recipient);
			(
				recipient.clone(),
				state.status,
				state.attempts,
				state.warmup,
				state.next_attempt,
			)
		})
		.collect()
}

const FIVE: [&str; 5] = [
	"r1@gmail.com",
	"r2@gmail.com",
	"r3@gmail.com",
	"r4@gmail.com",
	"r5@gmail.com",
];

#[tokio::test]
async fn recipients_over_the_cap_wait_without_an_attempt_or_a_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, now, _) = capped_worker(dir.path(), &FIVE, &remote);

	worker.pass().await.expect("pass");

	assert_eq!(remote.received().len(), 1, "one transaction for the burst");
	assert_eq!(
		remote.received()[0].recipients,
		["r1@gmail.com", "r2@gmail.com", "r3@gmail.com"]
	);
	let waiting = |recipient: &str| {
		(
			recipient.to_string(),
			RecipientStatus::Pending,
			0,
			Some("gmail".to_string()),
			now + 1728,
		)
	};
	assert_eq!(
		states(&worker)[3..],
		[waiting("r4@gmail.com"), waiting("r5@gmail.com")]
	);
	let log = DeliveryLog::open(dir.path(), 30);
	let outcomes: Vec<_> = log
		.list(None, |_| true)
		.expect("log")
		.into_iter()
		.map(|record| (record.recipient, record.outcome))
		.collect();
	assert_eq!(
		outcomes,
		[
			("r1@gmail.com".to_string(), DeliveryOutcome::Delivered),
			("r2@gmail.com".to_string(), DeliveryOutcome::Delivered),
			("r3@gmail.com".to_string(), DeliveryOutcome::Delivered),
		],
		"waiting for the cap is not a deferral"
	);
}

#[tokio::test]
async fn a_closed_cap_is_not_even_connected_to_and_the_next_unit_goes_on_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, now, _) = capped_worker(dir.path(), &FIVE, &remote);
	worker.pass().await.expect("pass");
	assert_eq!(remote.connections(GMAIL_MX), 1);

	worker.set_now(now + 1727);
	worker.pass().await.expect("pass");
	assert_eq!(
		remote.connections(GMAIL_MX),
		1,
		"nothing while the cap is closed"
	);

	worker.set_now(now + 1728);
	worker.pass().await.expect("pass");
	assert_eq!(remote.connections(GMAIL_MX), 2);
	assert_eq!(remote.received()[1].recipients, ["r4@gmail.com"]);
	let r5 = &states(&worker)[4];
	assert_eq!(
		(r5.1, r5.2, r5.4),
		(RecipientStatus::Pending, 0, now + 2 * 1728)
	);
}

#[tokio::test]
async fn waiting_for_the_cap_does_not_use_the_give_up_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, now, _) = capped_worker(dir.path(), &FIVE, &remote);
	let worker = worker.with_max_age(600);
	worker.pass().await.expect("pass");

	// Past the window, the cap still closed: nothing moves.
	worker.set_now(now + 1700);
	worker.pass().await.expect("pass");
	let waiting: Vec<_> = states(&worker)[3..].iter().map(|state| state.1).collect();
	assert_eq!(
		waiting,
		[RecipientStatus::Pending, RecipientStatus::Pending]
	);

	// The cap opens and the first real attempt is deferred: the message
	// is older than the window, but its recipient has used one second of
	// it, so it stays queued.
	remote.hosted(
		"gmail.com",
		GMAIL_MX,
		Script::rcpt("r4@gmail.com", "450 4.2.0 greylisted"),
	);
	worker.set_now(now + 1728);
	worker.pass().await.expect("pass");
	assert_eq!(
		worker.spool.list().expect("list").len(),
		1,
		"the message is still queued, not expired"
	);
	let r4 = &states(&worker)[3];
	assert_eq!(
		(r4.1, r4.2, r4.3.as_deref()),
		(RecipientStatus::Pending, 1, None)
	);
}

#[tokio::test]
async fn new_mail_to_a_closed_group_is_not_connected_for() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, now, _) = capped_worker(dir.path(), &FIVE[..3], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(remote.connections(GMAIL_MX), 1, "the burst went out");

	// A new message for the group, never capped before, while it is closed.
	store(&worker.spool, &["late@gmail.com"]);
	worker.set_now(now + 10);
	worker.pass().await.expect("pass");
	assert_eq!(
		remote.connections(GMAIL_MX),
		1,
		"no connection while the cap is closed"
	);
	let late = worker
		.spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| worker.spool.load_envelope(id).expect("envelope"))
		.find(|envelope| envelope.recipients == ["late@gmail.com"])
		.expect("the new message");
	let state = late.recipient_state("late@gmail.com");
	assert_eq!(
		(state.attempts, state.warmup.as_deref(), state.next_attempt),
		(0, Some("gmail"), now + 1728)
	);
}

#[tokio::test]
async fn turning_the_warm_up_off_sends_the_waiting_recipients_at_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, now, warmup) = capped_worker(dir.path(), &FIVE, &remote);
	worker.pass().await.expect("pass");

	settings::save(dir.path(), &Settings::default()).expect("settings");
	warmup.reload(now + 20).expect("reload");
	worker.set_now(now + 20);
	worker.pass().await.expect("pass");

	assert_eq!(remote.copies("r4@gmail.com"), 1);
	assert_eq!(remote.copies("r5@gmail.com"), 1);
	assert!(
		worker.spool.list().expect("list").is_empty(),
		"all delivered"
	);
}

#[tokio::test]
async fn a_workspace_domain_counts_against_gmail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, _, warmup) = capped_worker(dir.path(), &["ceo@corp.example"], &remote);
	worker.pass().await.expect("pass");
	assert_eq!(remote.copies("ceo@corp.example"), 1);
	let (_, state) = warmup.snapshot();
	assert_eq!(state.group(Group::Gmail).sent, 1);
	assert_eq!(state.group(Group::Other).sent, 0);
}

#[test]
fn only_a_remote_reply_counts_as_offered() {
	for (reason, offered) in [
		("421 4.7.0 slow down", true),
		("550-5.7.1 multi line", true),
		("250", true),
		("connection refused", false),
		("delivery attempt timed out after 300s", false),
		("4210 not a code", false),
		("", false),
	] {
		assert_eq!(super::is_reply(reason), offered, "{reason}");
	}
}

#[test]
fn time_waiting_for_the_cap_is_kept_across_waits() {
	let mut state = crate::storage::RecipientState::default();
	state.wait_for_cap("gmail", 500, 100);
	state.wait_for_cap("gmail", 900, 300);
	assert_eq!((state.capped_at, state.warmup_wait(400)), (100, 300));
	state.end_cap_wait(400);
	state.wait_for_cap("gmail", 2000, 1000);
	assert_eq!(state.warmup_wait(1100), 400);
	state.end_cap_wait(1200);
	assert_eq!(
		(state.warmup.as_deref(), state.waited, state.capped_at),
		(None, 500, 0)
	);
}
