//! An exchanger that turns the session away before the mail transaction
//! (a 4xx greeting, a failed TLS handshake) is passed over for the next one
//! in the same attempt (RFC 5321 section 5.1). Once the transaction has
//! begun, its answers are about the message, and they stand.

use super::*;
use crate::queue::test_remote::{FakeRemote, Hang, Received, Script};
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
	assert!(
		worker.spool.load_holds().expect("holds").is_empty(),
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
	assert!(
		worker
			.spool
			.load_holds()
			.expect("holds")
			.contains_key(DOMAIN)
	);
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

	assert_eq!(
		state(&worker).last_error.as_deref(),
		Some("timed out after 300s waiting for the greeting")
	);
	let holds = worker.spool.load_holds().expect("holds");
	assert_eq!(
		holds.get(DOMAIN).map(|hold| hold.reason.as_str()),
		Some("421 4.7.0 slow down")
	);
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
