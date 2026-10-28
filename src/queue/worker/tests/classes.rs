//! The remote's reply decides what happens to a recipient: retried, bounced,
//! suppressed or reported as a reputation problem.

use super::*;
use crate::queue::SuppressionList;
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use std::collections::BTreeMap;

const SENDER: &str = "alice@sender.example";

fn spool_to(dir: &std::path::Path, recipients: &[&str]) -> FsSpool {
	let spool = FsSpool::open(dir).expect("open spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: SENDER.into(),
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

/// A worker against `remote`, with a bounce sink, a suppression list and
/// metrics, giving up after one hour.
fn worker(
	dir: &std::path::Path,
	spool: FsSpool,
	remote: &FakeRemote,
) -> (Worker, Arc<MemorySink>, Arc<crate::metrics::Metrics>) {
	let bounces = Arc::new(MemorySink::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>)
		.with_suppression(SuppressionList::open(dir).expect("suppression"))
		.with_metrics(metrics.clone())
		.with_max_age(3600);
	(worker, bounces, metrics)
}

fn suppressed(dir: &std::path::Path, recipient: &str) -> bool {
	let list = SuppressionList::open(dir).expect("suppression");
	list.is_suppressed(recipient) || list.is_suppressed_for(SENDER, recipient)
}

#[tokio::test]
async fn the_bounce_quotes_the_remote_reply_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.1.1 no such user"),
	);
	let (worker, bounces, _) = worker(dir.path(), spool, &remote);

	worker.pass().await.expect("pass");

	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1);
	let diagnostic = bodies[0]
		.lines()
		.find(|line| line.starts_with("Diagnostic-Code:"))
		.unwrap_or_default();
	assert_eq!(diagnostic, "Diagnostic-Code: smtp; 550 5.1.1 no such user");
}

#[tokio::test]
async fn mailbox_full_is_retried_until_expiry_and_never_suppressed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let start = created(&spool);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "552 5.2.2 mailbox full"),
	);
	let (worker, bounces, _) = worker(dir.path(), spool, &remote);

	worker.set_now(start + 1);
	worker.pass().await.expect("pass");
	assert!(
		bounces.messages().is_empty(),
		"a full mailbox is retried, not bounced"
	);
	assert_eq!(worker.spool.list().expect("list").len(), 1);

	worker.set_now(start + 3601);
	worker.pass().await.expect("pass");
	assert!(worker.spool.list().expect("list").is_empty());
	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1, "bounced once the message expired");
	assert!(
		bodies[0].contains("Diagnostic-Code: smtp; 552 5.2.2 mailbox full\r\n"),
		"the bounce gives the mailbox-full reply"
	);
	assert!(
		!suppressed(dir.path(), "carol@remote.example"),
		"a full mailbox is not a bad address"
	);
}

#[tokio::test]
async fn a_policy_rejection_is_counted_as_a_reputation_problem() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.7.1 rejected by policy"),
	);
	let (worker, bounces, metrics) = worker(dir.path(), spool, &remote);

	worker.pass().await.expect("pass");

	assert_eq!(bounces.messages().len(), 1, "bounced for this message");
	assert!(
		!suppressed(dir.path(), "carol@remote.example"),
		"a policy refusal says nothing about the address"
	);
	assert!(
		metrics
			.render()
			.contains("mail_outbound_policy_rejected_total 1\n"),
		"the policy rejection must be counted"
	);
}

#[tokio::test]
async fn a_message_too_big_bounces_every_accepted_recipient_without_suppressing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["bob@remote.example", "carol@remote.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script {
			data: Some("552 5.3.4 message too big".into()),
			..Script::default()
		},
	);
	let (worker, bounces, _) = worker(dir.path(), spool, &remote);

	worker.pass().await.expect("pass");

	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1);
	assert_eq!(bodies[0].matches("Status: 5.3.4\r\n").count(), 2);
	for recipient in ["bob@remote.example", "carol@remote.example"] {
		assert!(
			!suppressed(dir.path(), recipient),
			"too big is about the message, not {recipient}"
		);
	}
}

#[tokio::test]
async fn a_disabled_mailbox_bounces_without_suppressing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.2.1 mailbox disabled"),
	);
	let (worker, bounces, _) = worker(dir.path(), spool, &remote);

	worker.pass().await.expect("pass");

	assert_eq!(bounces.messages().len(), 1);
	assert!(
		!suppressed(dir.path(), "carol@remote.example"),
		"a disabled mailbox is not suppressed"
	);
}

#[tokio::test]
async fn a_bad_address_is_suppressed_for_its_sender_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@remote.example"]);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.1.1 no such user"),
	);
	let (worker, _, _) = worker(dir.path(), spool, &remote);

	worker.pass().await.expect("pass");

	let list = SuppressionList::open(dir.path()).expect("suppression");
	assert!(list.is_suppressed("carol@remote.example"));
	assert!(list.is_suppressed_for(SENDER, "carol@remote.example"));
}

/// A recipient domain publishing a null MX (RFC 7505).
struct NullMx;

impl crate::queue::Connector for NullMx {
	fn connect(
		&self,
		domain: &str,
		_policy: Option<&crate::mtasts::Policy>,
	) -> crate::queue::resolver::ConnectFuture<'_> {
		let reason = format!("556 5.1.10 {domain} accepts no mail (null MX)");
		Box::pin(async move { Err(DeliveryError::Permanent(reason)) })
	}
}

#[tokio::test]
async fn a_null_mx_domain_bounces_at_once_and_is_suppressed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_to(dir.path(), &["carol@nomail.example"]);
	let bounces = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, Arc::new(NullMx), "mail.sender.example")
		.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>)
		.with_suppression(SuppressionList::open(dir.path()).expect("suppression"));

	worker.pass().await.expect("pass");

	assert!(
		worker.spool.list().expect("list").is_empty(),
		"never retried"
	);
	let bodies = bodies(&bounces);
	assert_eq!(bodies.len(), 1);
	assert!(bodies[0].contains("Status: 5.1.10\r\n"), "{}", bodies[0]);
	assert!(suppressed(dir.path(), "carol@nomail.example"));
}
