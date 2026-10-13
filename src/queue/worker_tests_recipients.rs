//! Each recipient of a spooled message has its own outcome: one refusal or
//! one slow domain must not decide what happens to the others.

use super::*;
use crate::queue::SuppressionList;
use crate::queue::test_remote::{FakeRemote, Received, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};

const SENDER: &str = "alice@sender.example";

fn spool_to(dir: &std::path::Path, recipients: &[&str]) -> FsSpool {
	let spool = FsSpool::open(dir).expect("open spool");
	spool
		.store(&AcceptedMessage {
			reverse_path: SENDER.into(),
			recipients: recipients.iter().map(|r| r.to_string()).collect(),
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("store");
	spool
}

fn created(spool: &FsSpool) -> u64 {
	spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7 timestamp")
		.to_unix()
		.0
}

fn bodies(sink: &MemorySink) -> Vec<String> {
	sink.messages()
		.iter()
		.map(|m| String::from_utf8_lossy(&m.data).to_string())
		.collect()
}

#[tokio::test]
async fn one_refused_recipient_does_not_stop_the_others_in_its_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example", "bob@remote.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.1.1 no such user"),
	);
	let bounces = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>);

	let delivered = worker.pass().await.expect("pass");

	assert_eq!(
		remote.received(),
		vec![Received {
			host: "mx.remote.example".into(),
			recipients: vec!["bob@remote.example".into()],
		}],
		"the accepted recipient must still get the message"
	);
	assert_eq!(delivered, 1);
	assert!(worker.spool.list().expect("list").is_empty());
	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1, "one bounce for the refused recipient");
	assert!(
		bodies[0].contains("Final-Recipient: rfc822; carol@remote.example"),
		"bounce must name carol"
	);
	assert!(
		!bodies[0].contains("bob@remote.example"),
		"bounce must not name the delivered recipient"
	);
}

#[tokio::test]
async fn a_later_domain_deferral_does_not_resend_to_an_earlier_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["bob@a.example", "dan@b.example"]);
	let start = created(&spool);
	let remote = FakeRemote::default();
	remote.script(
		"b.example",
		Script::rcpt("dan@b.example", "451 4.3.0 try again later"),
	);
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");

	for hours in [0u64, 1, 2] {
		worker.set_now(start + hours * 3600 + 1);
		worker.pass().await.expect("pass");
	}

	assert_eq!(
		remote.copies("bob@a.example"),
		1,
		"a retry for b.example must not send a.example a second copy"
	);
	assert_eq!(remote.copies("dan@b.example"), 0);
	assert_eq!(
		worker.spool.list().expect("list").len(),
		1,
		"dan@ still queued"
	);
}

#[tokio::test]
async fn a_later_domain_refusal_keeps_the_earlier_delivery_and_its_recipient() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["bob@a.example", "dan@b.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"b.example",
		Script::rcpt("dan@b.example", "550 5.1.1 no such user"),
	);
	let bounces = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>)
		.with_suppression(SuppressionList::open(dir.path()).expect("suppression"));

	worker.pass().await.expect("pass");

	assert_eq!(remote.copies("bob@a.example"), 1);
	assert!(worker.spool.list().expect("list").is_empty());
	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1);
	assert!(
		!bodies[0].contains("bob@a.example"),
		"the bounce must not report the delivered recipient as failed"
	);
	let suppression = SuppressionList::open(dir.path()).expect("suppression");
	assert!(
		!suppression.is_suppressed("bob@a.example")
			&& !suppression.is_suppressed_for(SENDER, "bob@a.example"),
		"a delivered recipient must never be suppressed"
	);
	assert!(suppression.is_suppressed("dan@b.example"));
}

/// Copy every file of the spool's `new/` directory aside, or back.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
	std::fs::create_dir_all(to).expect("mkdir");
	for entry in std::fs::read_dir(from).expect("read dir") {
		let entry = entry.expect("entry");
		std::fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
	}
}

#[tokio::test]
async fn a_crash_before_the_record_resends_at_most_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["bob@a.example", "dan@b.example"]);
	let start = created(&spool);
	let remote = FakeRemote::default();
	remote.script(
		"b.example",
		Script::rcpt("dan@b.example", "451 4.3.0 try again later"),
	);
	let new = dir.path().join("spool/new");
	let saved = dir.path().join("saved");
	copy_dir(&new, &saved);

	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");
	worker.set_now(start + 1);
	worker.pass().await.expect("pass");
	assert_eq!(remote.copies("bob@a.example"), 1);
	drop(worker);

	// The process died after a.example answered 250 to DATA but before the
	// outcome reached the disk: the spool is exactly as it was before.
	copy_dir(&saved, &new);
	let restarted = Worker::new(
		FsSpool::open(dir.path()).expect("reopen"),
		Arc::new(remote.clone()),
		"mail.sender.example",
	);
	for hours in [1u64, 2, 3, 4] {
		restarted.set_now(start + hours * 3600);
		restarted.pass().await.expect("pass");
	}

	assert_eq!(
		remote.copies("bob@a.example"),
		2,
		"one crash may cost one duplicate, never more"
	);
}

#[tokio::test]
async fn an_entry_written_before_per_recipient_state_still_delivers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let id = uuid::Uuid::now_v7();
	let new = dir.path().join("spool/new");
	// The envelope exactly as releases before per-recipient state wrote it.
	let legacy = format!(
		r#"{{"id":"{id}","reverse_path":"{SENDER}","recipients":["bob@a.example","dan@b.example"],"attempts":2,"next_attempt":0,"require_tls":false,"no_dsn":[],"delay_warned":false}}"#
	);
	std::fs::write(new.join(format!("{id}.json")), legacy).expect("envelope");
	std::fs::write(
		new.join(format!("{id}.eml")),
		b"Subject: old\r\n\r\nbody\r\n",
	)
	.expect("eml");
	let remote = FakeRemote::default();
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");

	assert_eq!(worker.pass().await.expect("pass"), 1);

	assert_eq!(remote.copies("bob@a.example"), 1);
	assert_eq!(remote.copies("dan@b.example"), 1);
	assert!(worker.spool.list().expect("list").is_empty());
}
