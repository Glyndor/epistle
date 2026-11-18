//! Evidence tests for outcomes that wait, are retried or are settled by the next worker.

use super::*;

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

#[tokio::test]
async fn an_outcome_keeps_the_retention_of_its_acceptance_not_the_policy_of_the_day_it_arrives() {
	use crate::evidence::policy::{Mode, Policy, Rule, Scope, save};
	let dir = tempfile::tempdir().expect("tempdir");
	// Accepted with a year of retention (the helper stores 365)...
	let spool = store(dir.path(), &["ana@remote.example"], true);
	// ...and the operator shortens the policy before the delivery.
	let mut policy = Policy::default();
	policy.set(Rule {
		scope: Scope::Server,
		class: Some(MailClass::Transactional),
		mode: Mode::Metadata,
		days: 30,
	});
	save(&dir.path().join("evidence"), &policy).expect("policy");
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	worker(dir.path(), spool, &remote)
		.pass()
		.await
		.expect("pass");
	let written = outcomes(dir.path());
	assert_eq!(written.len(), 1);
	assert_eq!(
		written[0].retain_days, 365,
		"the policy of the day was used"
	);
}

#[tokio::test]
async fn a_delivery_whose_outcome_was_never_attempted_is_written_by_the_next_worker() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["ana@remote.example"], true);
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	// A worker that dies before it writes anything: no evidence service, so
	// the delivery is settled and nothing is recorded.
	Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_suppression(SuppressionList::open(dir.path()).expect("suppression"))
		.pass()
		.await
		.expect("pass");
	assert_eq!(remote.copies("ana@remote.example"), 1);
	assert!(outcomes(dir.path()).is_empty());
	let left = FsSpool::open(dir.path())
		.expect("spool")
		.list()
		.expect("list");
	assert_eq!(left.len(), 1, "the entry went with its outcome unwritten");
	// The next worker has the service and finds what is owed.
	worker(
		dir.path(),
		FsSpool::open(dir.path()).expect("spool"),
		&remote,
	)
	.pass()
	.await
	.expect("pass");
	let written = outcomes(dir.path());
	assert_eq!(written.len(), 1, "{written:?}");
	assert_eq!(written[0].result, OutcomeKind::Delivered);
	assert_eq!(remote.copies("ana@remote.example"), 1, "sent again");
	assert!(
		FsSpool::open(dir.path())
			.expect("spool")
			.list()
			.expect("list")
			.is_empty()
	);
}

#[tokio::test]
async fn the_running_worker_retries_waiting_outcomes_without_a_pass() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["ana@remote.example"], true);
	let blocked = block_evidence(dir.path());
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	let running = Arc::new(worker(dir.path(), spool, &remote));
	let task = tokio::spawn(Arc::clone(&running).run(std::time::Duration::from_millis(20)));
	let root = dir.path().to_path_buf();
	tokio::task::yield_now().await;
	// Delivered, and the entry waits for its outcome.
	let started = std::time::Instant::now();
	while remote.copies("ana@remote.example") == 0 {
		assert!(
			started.elapsed() < std::time::Duration::from_secs(10),
			"never delivered"
		);
		tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	}
	std::fs::remove_dir(&blocked).expect("unblock");
	let started = std::time::Instant::now();
	while outcomes(&root).is_empty() {
		assert!(
			started.elapsed() < std::time::Duration::from_secs(10),
			"the waiting outcome was never written"
		);
		tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	}
	task.abort();
	assert_eq!(remote.copies("ana@remote.example"), 1);
}

#[test]
fn an_entry_with_outcomes_waiting_cannot_be_removed_from_outside_the_worker() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["ana@remote.example"], true);
	let id = spool.list().expect("list")[0];
	spool
		.update_envelope(id, |envelope| {
			envelope
				.outcomes_pending
				.push(crate::storage::PendingOutcome {
					recipient: "ana@remote.example".into(),
					result: OutcomeKind::Delivered,
					attempt: 1,
					remote: None,
					reply: None,
					tls: None,
					dane: false,
					mta_sts: None,
				});
		})
		.expect("pending");
	let refused = spool
		.remove(id)
		.expect_err("removed with an outcome waiting");
	assert!(
		refused.to_string().contains("evidence outcomes waiting"),
		"{refused}"
	);
	assert_eq!(spool.list().expect("list").len(), 1);
}

#[test]
fn the_bare_spool_refuses_transactional_mail_it_would_queue_without_evidence() {
	use crate::smtp::sink::{MessageSink, Submission};
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let message = AcceptedMessage {
		reverse_path: "notices@sender.example".into(),
		recipients: vec!["ana@remote.example".into()],
		data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let refused = spool.submit(
		message.clone(),
		uuid::Uuid::now_v7(),
		"notices",
		&Submission::of_class(MailClass::Transactional),
	);
	assert!(matches!(
		refused,
		Err(crate::smtp::sink::SinkError::EvidenceUnavailable(_))
	));
	assert!(spool.list().expect("list").is_empty());
	spool
		.submit(
			message,
			uuid::Uuid::now_v7(),
			"notices",
			&Submission::default(),
		)
		.expect("personal mail");
	assert_eq!(spool.list().expect("list").len(), 1);
}

#[tokio::test]
async fn a_clock_that_jumps_a_year_ahead_does_not_expire_mail_that_only_waited() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["late@remote.example"], true);
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("late@remote.example", "451 4.3.0 later"),
	);
	let worker = worker(dir.path(), spool, &remote).with_max_age(3600);
	let time = worker.evidence.as_ref().expect("evidence").time();
	worker.pass().await.expect("pass");
	// Seconds later by the monotonic clock, a year later by the wall clock.
	time.skew(400 * 86_400);
	worker.pass().await.expect("pass");
	assert!(
		outcomes(dir.path()).is_empty(),
		"mail that only waited was given up on"
	);
	assert_eq!(worker.spool.list().expect("list").len(), 1);
}

#[tokio::test]
async fn what_a_removed_entry_was_owed_is_written_from_the_entry_as_it_was() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = store(dir.path(), &["late@remote.example"], true);
	let mut envelope = spool
		.load_envelope(spool.list().expect("list")[0])
		.expect("envelope");
	envelope
		.outcomes_pending
		.push(crate::storage::PendingOutcome {
			recipient: "late@remote.example".into(),
			result: OutcomeKind::Delivered,
			attempt: 1,
			remote: Some("mx.remote.example".into()),
			reply: None,
			tls: None,
			dane: false,
			mta_sts: None,
		});
	let remote = FakeRemote::default();
	let worker = worker(dir.path(), spool, &remote);
	worker.write_owed(&envelope);
	let written = outcomes(dir.path());
	assert_eq!(written.len(), 1);
	assert_eq!(written[0].result, OutcomeKind::Delivered);
}

#[allow(unused_imports)]
use super::super::evidence;
