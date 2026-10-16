//! The worker records the outcome of every recipient of a message that
//! keeps evidence, and of no other message.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::evidence::MailClass;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Entry, Outcome, OutcomeKind};
use crate::evidence::service::EvidenceService;
use crate::evidence::verify::walk_day;
use crate::queue::SuppressionList;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use crate::storage::{MessageCrypto, StoreOptions};

fn store(dir: &std::path::Path, recipients: &[&str], evidence: bool) -> FsSpool {
	let spool = FsSpool::open(dir).expect("spool");
	let message = AcceptedMessage {
		reverse_path: "notices@sender.example".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: Aviso\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let recorded = |_: &[u8]| Ok(());
	let options = StoreOptions {
		account: Some("notices"),
		extra: &BTreeMap::new(),
		class: MailClass::Transactional,
		evidence: evidence.then_some(&recorded as &dyn Fn(&[u8]) -> std::io::Result<()>),
	};
	spool
		.store_with(&message, uuid::Uuid::now_v7(), &options)
		.expect("store");
	spool
}

fn worker(dir: &std::path::Path, spool: FsSpool, remote: &FakeRemote) -> Worker {
	let service = Arc::new(
		EvidenceService::open(dir, Vec::new(), MessageCrypto::disabled()).expect("evidence"),
	);
	Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_suppression(SuppressionList::open(dir).expect("suppression"))
		.with_evidence(service)
}

fn outcomes(dir: &std::path::Path) -> Vec<Outcome> {
	let root = dir.join("evidence");
	let mut out = Vec::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		walk_day(&root, day, None, |_, record, _| {
			if let Entry::Outcome(outcome) = &record.entry {
				out.push(outcome.clone());
			}
		})
		.expect("walk");
	}
	out.sort_by(|a, b| a.recipient.cmp(&b.recipient));
	out
}

#[tokio::test]
async fn delivered_bounced_and_suppressed_recipients_are_recorded() {
	let dir = tempfile::tempdir().expect("tempdir");
	SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@third.example");
	let spool = store(
		dir.path(),
		&[
			"ana@remote.example",
			"bad@other.example",
			"gone@third.example",
		],
		true,
	);
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	remote.script(
		"other.example",
		Script::rcpt("bad@other.example", "550 5.1.1 no such user"),
	);
	worker(dir.path(), spool, &remote)
		.pass()
		.await
		.expect("pass");
	let outcomes = outcomes(dir.path());
	assert_eq!(outcomes.len(), 3);
	let ana = &outcomes[0];
	assert_eq!(ana.result, OutcomeKind::Delivered);
	assert_eq!(ana.remote.as_deref(), Some("mx.remote.example"));
	assert_eq!(ana.reply.as_deref(), Some("250 2.0.0 queued"));
	assert_eq!(ana.class, MailClass::Transactional);
	assert_eq!(ana.attempt, 1);
	let bad = &outcomes[1];
	assert_eq!(bad.result, OutcomeKind::Bounced);
	assert_eq!(bad.reply.as_deref(), Some("550 5.1.1 no such user"));
	assert_eq!(outcomes[2].result, OutcomeKind::Suppressed);
}

#[tokio::test]
async fn an_expired_recipient_is_recorded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["late@remote.example"], true);
	let created = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("late@remote.example", "451 4.3.0 later"),
	);
	let worker = worker(dir.path(), spool, &remote).with_max_age(3600);
	worker.set_now(created + 1);
	worker.pass().await.expect("pass");
	assert!(
		outcomes(dir.path()).is_empty(),
		"a deferral is not an outcome"
	);
	worker.set_now(created + 3601);
	worker.pass().await.expect("pass");
	let outcomes = outcomes(dir.path());
	assert_eq!(outcomes.len(), 1);
	assert_eq!(outcomes[0].result, OutcomeKind::Expired);
	assert_eq!(outcomes[0].reply.as_deref(), Some("451 4.3.0 later"));
}

#[tokio::test]
async fn a_message_without_evidence_records_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["ana@remote.example"], false);
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	worker(dir.path(), spool, &remote)
		.pass()
		.await
		.expect("pass");
	assert!(outcomes(dir.path()).is_empty());
}

/// Put a directory where today's day file must go, so no record can be written.
fn block_evidence(dir: &std::path::Path) -> std::path::PathBuf {
	let today = crate::evidence::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	let blocked = dir
		.join("evidence/chain")
		.join(format!("{}.jsonl", today.name()));
	std::fs::create_dir_all(&blocked).expect("block the day file");
	blocked
}

#[tokio::test]
async fn an_outcome_that_cannot_be_written_is_kept_and_written_later_without_sending_again() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["ana@remote.example"], true);
	let blocked = block_evidence(dir.path());
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	let worker = worker(dir.path(), spool, &remote);
	worker.pass().await.expect("pass");
	assert_eq!(remote.copies("ana@remote.example"), 1, "delivered once");
	let left = FsSpool::open(dir.path())
		.expect("spool")
		.list()
		.expect("list");
	assert_eq!(
		left.len(),
		1,
		"the entry was settled with its outcome unwritten"
	);
	assert!(outcomes(dir.path()).is_empty());
	// While it cannot be written the entry waits, and is not sent again.
	worker.pass().await.expect("pass");
	assert_eq!(remote.copies("ana@remote.example"), 1);
	assert_eq!(
		FsSpool::open(dir.path())
			.expect("spool")
			.list()
			.expect("list")
			.len(),
		1
	);
	// The evidence log takes records again.
	std::fs::remove_dir(&blocked).expect("unblock");
	worker.pass().await.expect("pass");
	let written = outcomes(dir.path());
	assert_eq!(written.len(), 1, "{written:?}");
	assert_eq!(written[0].result, OutcomeKind::Delivered);
	assert_eq!(written[0].reply.as_deref(), Some("250 2.0.0 queued"));
	assert_eq!(remote.copies("ana@remote.example"), 1, "sent again");
	assert!(
		FsSpool::open(dir.path())
			.expect("spool")
			.list()
			.expect("list")
			.is_empty(),
		"the entry stayed after its outcome was written"
	);
}

#[tokio::test]
async fn personal_mail_is_still_settled_when_its_outcome_cannot_be_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["ana@remote.example"], true);
	// The entry keeps evidence but is not transactional.
	spool
		.update_envelope(spool.list().expect("list")[0], |envelope| {
			envelope.class = MailClass::Personal;
		})
		.expect("class");
	block_evidence(dir.path());
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	worker(dir.path(), spool, &remote)
		.pass()
		.await
		.expect("pass");
	assert!(
		FsSpool::open(dir.path())
			.expect("spool")
			.list()
			.expect("list")
			.is_empty(),
		"personal mail waits for nothing"
	);
}
