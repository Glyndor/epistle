//! An exchanger that turns the session away before the mail transaction
//! (a 4xx greeting, a failed TLS handshake) is passed over for the next one
//! in the same attempt (RFC 5321 section 5.1). Once the transaction has
//! begun, its answers are about the message, and they stand.

use super::*;
use crate::queue::destination::Destination;
use crate::queue::tests::test_remote::{FakeRemote, Hang, Received, Script};
use crate::smtp::session::AcceptedMessage;
use crate::storage::RecipientStatus;

const DOMAIN: &str = "multi.example";
const RECIPIENT: &str = "bob@multi.example";

fn worker_for(dir: &std::path::Path, remote: &FakeRemote) -> Worker {
	let spool = FsSpool::open(dir).expect("open spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec![RECIPIENT.to_string()],
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
	Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
}

fn greeting(reply: &str) -> Script {
	Script {
		greeting: Some(reply.to_string()),
		..Script::default()
	}
}

/// The hold of `key` now, as the spool shows it.
fn hold(worker: &Worker, key: &Destination) -> Option<crate::queue::backoff::Hold> {
	crate::queue::backoff::Holds::read(&worker.spool)
		.expect("holds")
		.held(key, worker.now_epoch())
		.cloned()
}

fn state(worker: &Worker) -> crate::storage::RecipientState {
	let id = worker.spool.list().expect("list")[0];
	worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state(RECIPIENT)
}

#[tokio::test]
async fn a_4xx_greeting_moves_on_to_the_next_exchanger() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.exchangers(
		DOMAIN,
		vec![greeting("421 4.3.2 shutting down"), Script::default()],
	);
	let worker = worker_for(dir.path(), &remote);

	assert_eq!(worker.pass().await.expect("pass"), 1);

	assert_eq!(
		remote.received(),
		vec![Received {
			host: "mx2.multi.example".into(),
			recipients: vec![RECIPIENT.into()],
		}]
	);
	assert_eq!(remote.connections("mx1.multi.example"), 1);
	assert!(worker.spool.list().expect("list").is_empty());
	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN)),
		None,
		"the domain delivered, so it is not held off"
	);
}

#[tokio::test]
async fn a_failed_tls_handshake_moves_on_to_the_next_exchanger() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let broken_tls = Script {
		starttls: true,
		..Script::default()
	};
	remote.exchangers(DOMAIN, vec![broken_tls, Script::default()]);
	let worker = worker_for(dir.path(), &remote);

	assert_eq!(worker.pass().await.expect("pass"), 1);

	assert_eq!(remote.copies(RECIPIENT), 1);
	assert_eq!(remote.received()[0].host, "mx2.multi.example");
}

#[tokio::test]
async fn when_every_exchanger_turns_the_session_away_the_recipient_waits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.exchangers(
		DOMAIN,
		vec![
			greeting("421 4.7.0 slow down"),
			greeting("421 4.7.0 slow down"),
		],
	);
	let worker = worker_for(dir.path(), &remote);

	assert_eq!(worker.pass().await.expect("pass"), 0);

	assert_eq!(remote.connections("mx1.multi.example"), 1);
	assert_eq!(remote.connections("mx2.multi.example"), 1);
	let state = state(&worker);
	assert_eq!(
		(state.status, state.attempts),
		(RecipientStatus::Pending, 1)
	);
	assert_eq!(state.last_error.as_deref(), Some("421 4.7.0 slow down"));
	assert_eq!(state.remote.as_deref(), Some("mx2.multi.example"));
	assert!(hold(&worker, &Destination::domain(DOMAIN)).is_some());
	assert!(hold(&worker, &Destination::exchanger("mx2.multi.example")).is_some());
}

#[tokio::test(start_paused = true)]
async fn a_slow_down_from_an_earlier_exchanger_still_holds_the_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.exchangers(
		DOMAIN,
		vec![
			greeting("421 4.7.0 slow down"),
			Script::hang(Hang::Greeting),
		],
	);
	let worker = worker_for(dir.path(), &remote);

	worker.pass().await.expect("pass");

	// The recipient waits for the slow-down, recorded against the
	// exchanger that asked, though the last one tried timed out.
	let state = state(&worker);
	assert_eq!(state.last_error.as_deref(), Some("421 4.7.0 slow down"));
	assert_eq!(state.remote.as_deref(), Some("mx1.multi.example"));
	assert_eq!(
		hold(&worker, &Destination::domain(DOMAIN)).map(|hold| hold.reason),
		Some("421 4.7.0 slow down".to_string())
	);
	assert!(hold(&worker, &Destination::exchanger("mx1.multi.example")).is_some());
}

#[tokio::test]
async fn a_refusal_inside_the_transaction_does_not_try_another_exchanger() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.exchangers(
		DOMAIN,
		vec![
			Script::rcpt(RECIPIENT, "450 4.2.0 mailbox busy"),
			Script::default(),
		],
	);
	let worker = worker_for(dir.path(), &remote);

	assert_eq!(worker.pass().await.expect("pass"), 0);

	assert_eq!(remote.connections("mx2.multi.example"), 0);
	assert_eq!(
		state(&worker).last_error.as_deref(),
		Some("450 4.2.0 mailbox busy")
	);
}

#[tokio::test]
async fn a_deferred_mail_command_does_not_try_another_exchanger() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let busy = Script {
		mail: Some("451 4.3.0 try again later".into()),
		..Script::default()
	};
	remote.exchangers(DOMAIN, vec![busy, Script::default()]);
	let worker = worker_for(dir.path(), &remote);

	assert_eq!(worker.pass().await.expect("pass"), 0);

	assert_eq!(remote.connections("mx2.multi.example"), 0);
	assert_eq!(
		state(&worker).last_error.as_deref(),
		Some("451 4.3.0 try again later")
	);
}

/// A domain publishing 50 exchangers, every one of which accepts the
/// connection and never greets.
fn fifty_silent_exchangers(remote: &FakeRemote) {
	remote.exchangers(DOMAIN, vec![Script::hang(Hang::Greeting); 50]);
}

#[tokio::test(start_paused = true)]
async fn a_domain_with_fifty_silent_exchangers_is_tried_on_five() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	fifty_silent_exchangers(&remote);
	let worker = worker_for(dir.path(), &remote);
	let started = tokio::time::Instant::now();

	assert_eq!(worker.pass().await.expect("pass"), 0);

	let opened: Vec<usize> = (1..=50)
		.map(|n| remote.connections(&format!("mx{n}.{DOMAIN}")))
		.collect();
	assert_eq!(opened[..5], [1; 5]);
	assert!(opened[5..].iter().all(|count| *count == 0), "{opened:?}");
	assert_eq!(
		started.elapsed(),
		crate::queue::timeouts::GREETING * 5,
		"five greetings waited for, one after the other"
	);
	let state = state(&worker);
	assert_eq!(
		(state.status, state.attempts),
		(RecipientStatus::Pending, 1)
	);
}

#[tokio::test(start_paused = true)]
async fn one_delivery_attempt_ends_at_its_overall_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	fifty_silent_exchangers(&remote);
	let mut worker = worker_for(dir.path(), &remote);
	let limit = crate::queue::timeouts::GREETING * 2 + std::time::Duration::from_secs(60);
	worker.set_attempt_limit(limit);
	let started = tokio::time::Instant::now();

	worker.pass().await.expect("pass");

	assert_eq!(started.elapsed(), limit);
	assert_eq!(remote.connections("mx3.multi.example"), 1);
	assert_eq!(remote.connections("mx4.multi.example"), 0);
	let state = state(&worker);
	assert_eq!(
		(state.status, state.attempts),
		(RecipientStatus::Pending, 1)
	);
	assert_eq!(
		state.last_error.as_deref(),
		Some("delivery attempt timed out after 660s")
	);
}

#[tokio::test(start_paused = true)]
async fn the_per_domain_cap_holds_across_every_exchanger_of_the_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	fifty_silent_exchangers(&remote);
	let spool = FsSpool::open(dir.path()).expect("open spool");
	for n in 0..4 {
		spool
			.store(
				&AcceptedMessage {
					reverse_path: "alice@sender.example".into(),
					recipients: vec![format!("user{n}@{DOMAIN}")],
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
	let worker =
		Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example").with_concurrency(8, 1);

	worker.pass().await.expect("pass");

	assert_eq!(remote.most_at_once(DOMAIN), 1);
	let opened: usize = (1..=50)
		.map(|n| remote.connections(&format!("mx{n}.{DOMAIN}")))
		.sum();
	assert_eq!(opened, 4 * 5, "five exchangers for each of four messages");
}

#[tokio::test(start_paused = true)]
async fn the_attempt_limit_never_cuts_the_wait_for_the_reply_to_a_sent_message() {
	// The remote has the whole message when the attempt limit runs out:
	// giving up then would count it undelivered and send it again.
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(
		DOMAIN,
		Script {
			delay: Some(std::time::Duration::from_secs(120)),
			..Script::default()
		},
	);
	let mut worker = worker_for(dir.path(), &remote);
	worker.set_attempt_limit(std::time::Duration::from_secs(60));

	worker.pass().await.expect("pass");
	// Whatever the first attempt left pending is due again an hour on.
	tokio::time::sleep(std::time::Duration::from_secs(300)).await;
	worker.set_now(worker.now_epoch() + 3600);
	worker.pass().await.expect("second pass");
	tokio::time::sleep(std::time::Duration::from_secs(300)).await;

	assert_eq!(remote.copies(RECIPIENT), 1, "one copy, never a second");
	assert!(
		worker.spool.list().expect("list").is_empty(),
		"the entry is settled as delivered"
	);
}

#[tokio::test(start_paused = true)]
async fn a_remote_silent_after_the_message_still_frees_the_slot_in_bounded_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, Script::hang(Hang::DataEnd));
	let mut worker = worker_for(dir.path(), &remote);
	worker.set_attempt_limit(std::time::Duration::from_secs(60));
	let started = tokio::time::Instant::now();

	worker.pass().await.expect("pass");

	assert_eq!(started.elapsed(), crate::queue::timeouts::DATA_END);
	let state = state(&worker);
	assert_eq!(
		(state.status, state.attempts),
		(RecipientStatus::Pending, 1)
	);
	assert_eq!(
		state.last_error.as_deref(),
		Some("timed out after 600s waiting for the reply to the message")
	);
}
