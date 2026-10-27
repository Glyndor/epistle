//! Submissions that keep evidence, through the routing sink.

use std::path::Path;
use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::evidence::MailClass;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Entry, Record, sha256, to_hex};
use crate::evidence::service::EvidenceService;
use crate::evidence::verify::walk_day;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError, Submission};
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("notices@example.org".to_string(), "notices".to_string())],
	))
}

fn message(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "notices@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Message-ID: <n1@example.org>\r\nSubject: Aviso\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

fn sink(dir: &Path) -> (SplitDelivery, Arc<EvidenceService>) {
	let service = Arc::new(
		EvidenceService::open(dir, Vec::new(), MessageCrypto::disabled()).expect("evidence"),
	);
	// As after the server's first clean verification.
	service.set_gate(None);
	let split = SplitDelivery::new(dir, directory())
		.expect("sink")
		.with_evidence(Arc::clone(&service));
	(split, service)
}

fn records(dir: &Path) -> Vec<Record> {
	let root = dir.join("evidence");
	let mut out = Vec::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		walk_day(&root, day, None, |_, record, _| out.push(record.clone())).expect("walk");
	}
	out
}

fn transactional() -> Submission {
	Submission::of_class(MailClass::Transactional)
}

#[test]
fn transactional_mail_is_queued_with_its_acceptance_over_the_queued_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	let id = uuid::Uuid::now_v7();
	split
		.submit(
			message(&["student@example.net"]),
			id,
			"notices",
			&transactional(),
		)
		.expect("accepted");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(id).expect("queued");
	assert_eq!(entry.envelope.class, MailClass::Transactional);
	assert!(entry.envelope.evidence);
	let records = records(dir.path());
	assert_eq!(records.len(), 1);
	let Entry::Accepted(accepted) = &records[0].entry else {
		panic!("not an acceptance");
	};
	assert_eq!(accepted.spool_id, id);
	assert_eq!(accepted.sha256, to_hex(&sha256(&entry.data)));
}

#[test]
fn transactional_mail_is_refused_when_its_evidence_cannot_be_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	// A directory where the day file must go: the append fails, durably.
	let today = crate::evidence::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	std::fs::create_dir_all(
		dir.path()
			.join("evidence/chain")
			.join(format!("{}.jsonl", today.name())),
	)
	.expect("block the day file");
	let id = uuid::Uuid::now_v7();
	let result = split.submit(
		message(&["student@example.net"]),
		id,
		"notices",
		&transactional(),
	);
	assert!(
		matches!(result, Err(SinkError::EvidenceUnavailable(_))),
		"a transactional message without evidence was accepted"
	);
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(
		spool.list().expect("list").is_empty(),
		"the message was queued anyway"
	);
	assert!(
		spool.leftovers(10).expect("tmp").is_empty(),
		"staged files were left behind"
	);
}

#[test]
fn personal_mail_still_flows_when_evidence_cannot_be_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	let today = crate::evidence::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	std::fs::create_dir_all(
		dir.path()
			.join("evidence/chain")
			.join(format!("{}.jsonl", today.name())),
	)
	.expect("block the day file");
	split
		.submit(
			message(&["friend@example.net"]),
			uuid::Uuid::now_v7(),
			"notices",
			&Submission::default(),
		)
		.expect("personal mail keeps no evidence and is accepted");
}

#[test]
fn a_held_gate_refuses_transactional_mail_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, service) = sink(dir.path());
	service.set_gate(Some("the evidence does not verify".into()));
	let refused = split.submit(
		message(&["s@example.net"]),
		uuid::Uuid::now_v7(),
		"notices",
		&transactional(),
	);
	assert!(matches!(refused, Err(SinkError::EvidenceUnavailable(_))));
	split
		.submit(
			message(&["s@example.net"]),
			uuid::Uuid::now_v7(),
			"notices",
			&Submission::default(),
		)
		.expect("personal mail is not held");
	assert_eq!(records(dir.path()).len(), 0);
}

#[test]
fn without_an_evidence_log_transactional_mail_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let split = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let refused = split.submit(
		message(&["s@example.net"]),
		uuid::Uuid::now_v7(),
		"notices",
		&transactional(),
	);
	assert!(matches!(refused, Err(SinkError::EvidenceUnavailable(_))));
}

#[test]
fn a_local_recipient_gets_the_acceptance_before_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	split
		.submit(
			message(&["notices@example.org"]),
			uuid::Uuid::now_v7(),
			"notices",
			&transactional(),
		)
		.expect("delivered locally");
	let records = records(dir.path());
	assert!(matches!(records[0].entry, Entry::Accepted(_)));
}

fn outcomes_of(records: &[Record]) -> Vec<(String, crate::evidence::record::OutcomeKind)> {
	records
		.iter()
		.filter_map(|record| match &record.entry {
			Entry::Outcome(outcome) => Some((outcome.recipient.clone(), outcome.result)),
			_ => None,
		})
		.collect()
}

#[test]
fn a_recipient_delivered_here_has_its_ending_so_the_message_can_be_shown_whole() {
	use crate::evidence::record::OutcomeKind;
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	split
		.submit(
			message(&["notices@example.org"]),
			uuid::Uuid::now_v7(),
			"notices",
			&transactional(),
		)
		.expect("delivered locally");
	assert_eq!(
		outcomes_of(&records(dir.path())),
		vec![("notices@example.org".to_string(), OutcomeKind::Delivered)]
	);
	assert!(
		!records(dir.path())
			.iter()
			.any(|record| matches!(record.entry, Entry::Abandoned(_))),
		"a message delivered here is not one nothing was sent of"
	);
}

#[test]
fn with_local_and_remote_recipients_only_the_local_one_has_its_ending_at_once() {
	use crate::evidence::record::OutcomeKind;
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	split
		.submit(
			message(&["notices@example.org", "student@remote.example"]),
			uuid::Uuid::now_v7(),
			"notices",
			&transactional(),
		)
		.expect("routed");
	// The remote recipient waits in the queue for its own ending.
	assert_eq!(
		outcomes_of(&records(dir.path())),
		vec![("notices@example.org".to_string(), OutcomeKind::Delivered)]
	);
}

#[test]
fn a_queue_that_fails_after_the_local_delivery_does_not_make_the_message_abandoned() {
	use crate::evidence::record::OutcomeKind;
	let dir = tempfile::tempdir().expect("tempdir");
	let (split, _) = sink(dir.path());
	// The remote copy cannot be staged.
	std::fs::remove_dir_all(dir.path().join("spool/tmp")).expect("rm tmp");
	std::fs::write(dir.path().join("spool/tmp"), b"not a directory").expect("block");
	split
		.submit(
			message(&["notices@example.org", "student@remote.example"]),
			uuid::Uuid::now_v7(),
			"notices",
			&transactional(),
		)
		.expect_err("the remote copy was not queued");
	let found = records(dir.path());
	assert_eq!(
		outcomes_of(&found),
		vec![("notices@example.org".to_string(), OutcomeKind::Delivered)]
	);
	assert!(
		!found
			.iter()
			.any(|record| matches!(record.entry, Entry::Abandoned(_))),
		"nothing was sent, said a record, of a message that was delivered here"
	);
}

/// The crash test: a child process stores a transactional message and dies
/// (abort) between writing the evidence and queueing the message. The
/// parent then finds the record, the staged files, nothing queued, and
/// after the start-up reconciliation an `abandoned` record and no leftover.
#[test]
fn a_crash_between_the_evidence_and_the_queue_leaves_a_recoverable_state() {
	if let Some(dir) = std::env::var_os("EPISTLE_TEST_CRASH_DIR") {
		let (split, _) = sink(Path::new(&dir));
		let _ = split.submit(
			message(&["s@example.net"]),
			uuid::Uuid::now_v7(),
			"notices",
			&transactional(),
		);
		unreachable!("the store aborts before returning");
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
		.args([
			"--exact",
			"storage::routing::evidence::tests::a_crash_between_the_evidence_and_the_queue_leaves_a_recoverable_state",
			"--test-threads=1",
		])
		.env("EPISTLE_TEST_CRASH_DIR", dir.path())
		.env("EPISTLE_TEST_ABORT_AFTER_EVIDENCE", "1")
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::null())
		.status()
		.expect("run the child");
	assert!(!status.success(), "the child did not crash");
	use std::os::unix::process::ExitStatusExt;
	assert_eq!(
		status.signal(),
		Some(libc::SIGABRT),
		"the child did not abort"
	);
	let records_after_crash = records(dir.path());
	let Entry::Accepted(accepted) = &records_after_crash[0].entry else {
		panic!("the acceptance was not durable before the crash");
	};
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(
		spool.list().expect("list").is_empty(),
		"the message reached the queue"
	);
	let leftovers = spool.leftovers(10).expect("leftovers");
	assert_eq!(leftovers.len(), 1);
	assert_eq!(leftovers[0].id, accepted.spool_id);
	assert!(leftovers[0].evidence);
	// Start-up reconciliation.
	let (_, service) = sink(dir.path());
	let reconciled = crate::evidence::service::reconcile(&spool, &service).expect("reconcile");
	assert_eq!(reconciled, 1);
	let records = records(dir.path());
	assert!(
		matches!(&records[1].entry, Entry::Abandoned(abandoned) if abandoned.spool_id == accepted.spool_id),
		"no abandoned record for the lost acceptance"
	);
	assert!(spool.leftovers(10).expect("leftovers").is_empty());
}
