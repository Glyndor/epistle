//! The failure report (RFC 3464 DSN) and the delay warning carry one block
//! per recipient, each with its own status and the reply that caused it.

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use std::collections::BTreeMap;

fn spool_to(dir: &std::path::Path, recipients: &[&str]) -> FsSpool {
	let spool = FsSpool::open(dir).expect("open spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: recipients.iter().map(|r| r.to_string()).collect(),
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
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

/// The `message/delivery-status` block of `recipient` in a report.
fn block<'a>(body: &'a str, recipient: &str) -> &'a str {
	let start = body
		.find(&format!("Final-Recipient: rfc822; {recipient}\r\n"))
		.unwrap_or_else(|| panic!("no block for {recipient}"));
	let rest = &body[start..];
	&rest[..rest.find("\r\n\r\n").unwrap_or(rest.len())]
}

fn worker(spool: FsSpool, connector: Arc<dyn Connector>) -> (Worker, Arc<MemorySink>) {
	let bounces = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, connector, "mail.sender.example")
		.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>)
		.with_max_age(5 * 3600);
	(worker, bounces)
}

#[tokio::test]
async fn one_report_lists_each_failed_recipient_with_its_own_status() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example", "dave@remote.example"]);
	let remote = FakeRemote::default();
	let mut script = Script::rcpt("carol@remote.example", "550 5.1.1 no such user");
	script.rcpt.insert(
		"dave@remote.example".into(),
		"550 5.2.1 mailbox disabled".into(),
	);
	remote.script("remote.example", script);
	let (worker, bounces) = worker(spool, Arc::new(remote));

	worker.pass().await.expect("pass");

	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1, "one report for the message");
	assert_eq!(
		block(&bodies[0], "carol@remote.example"),
		"Final-Recipient: rfc822; carol@remote.example\r\n\
		 Action: failed\r\n\
		 Status: 5.1.1\r\n\
		 Remote-MTA: dns; mx.remote.example\r\n\
		 Diagnostic-Code: smtp; 550 5.1.1 no such user"
	);
	assert_eq!(
		block(&bodies[0], "dave@remote.example"),
		"Final-Recipient: rfc822; dave@remote.example\r\n\
		 Action: failed\r\n\
		 Status: 5.2.1\r\n\
		 Remote-MTA: dns; mx.remote.example\r\n\
		 Diagnostic-Code: smtp; 550 5.2.1 mailbox disabled"
	);
}

#[tokio::test]
async fn an_expired_deferral_is_reported_with_a_permanent_status() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let start = created(&spool);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "452 4.2.2 mailbox full"),
	);
	let (worker, bounces) = worker(spool, Arc::new(remote));

	worker.set_now(start + 5 * 3600 + 1);
	worker.pass().await.expect("pass");

	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1);
	assert_eq!(
		block(&bodies[0], "carol@remote.example"),
		"Final-Recipient: rfc822; carol@remote.example\r\n\
		 Action: failed\r\n\
		 Status: 5.2.2\r\n\
		 Remote-MTA: dns; mx.remote.example\r\n\
		 Diagnostic-Code: smtp; 452 4.2.2 mailbox full"
	);
}

#[tokio::test]
async fn an_expired_unreachable_recipient_reports_delivery_time_expired() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let start = created(&spool);
	let (worker, bounces) = worker(spool, Arc::new(super::base::DownConnector));

	worker.set_now(start + 5 * 3600 + 1);
	worker.pass().await.expect("pass");

	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1);
	// No server answered, so there is no SMTP diagnostic to quote; the
	// reason stays in the human-readable part.
	assert_eq!(
		block(&bodies[0], "carol@remote.example"),
		"Final-Recipient: rfc822; carol@remote.example\r\n\
		 Action: failed\r\n\
		 Status: 5.4.7"
	);
	assert!(bodies[0].contains("connection refused"));
}

#[tokio::test]
async fn the_delay_warning_names_only_the_pending_recipients() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["bob@a.example", "dan@b.example"]);
	let start = created(&spool);
	let remote = FakeRemote::default();
	remote.script(
		"b.example",
		Script::rcpt("dan@b.example", "451 4.3.0 try again later"),
	);
	let (worker, bounces) = worker(spool, Arc::new(remote));

	worker.set_now(start + 1);
	worker.pass().await.expect("pass");
	worker.set_now(start + 4 * 3600 + 1);
	worker.pass().await.expect("pass");

	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1, "one delay warning");
	assert!(
		!bodies[0].contains("bob@a.example"),
		"a delivered recipient is not delayed"
	);
	assert_eq!(
		block(&bodies[0], "dan@b.example"),
		"Final-Recipient: rfc822; dan@b.example\r\n\
		 Action: delayed\r\n\
		 Status: 4.3.0\r\n\
		 Remote-MTA: dns; mx.b.example\r\n\
		 Diagnostic-Code: smtp; 451 4.3.0 try again later"
	);
}
