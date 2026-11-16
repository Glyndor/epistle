//! Provider diagnostics reach the persisted delivery log without changing DSNs.

use super::backoff::{greeting, hold, worker_for};
use super::*;
use crate::queue::SuppressionList;
use crate::queue::destination::Destination;
use crate::queue::reply::{ProviderCause, provider_cause};
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::smtp::sink::MemorySink;
use crate::storage::{DeliveryLog, DeliveryOutcome, RecipientStatus};

#[tokio::test]
async fn each_provider_reply_logs_its_fixed_cause_and_bounces_or_pauses() {
	for (reply, cause, permanent) in [
		(
			"550 5.7.515 changed words",
			ProviderCause::DomainAuthentication,
			true,
		),
		(
			"550 5.7.26 changed words",
			ProviderCause::Unauthenticated,
			true,
		),
		("450 4.7.28 changed words", ProviderCause::RateLimit, false),
		(
			"550 5.7.1 [192.0.2.1] denied",
			ProviderCause::IpOrList,
			true,
		),
		(
			"451 [TSS04] changed words",
			ProviderCause::YahooThrottle,
			false,
		),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let remote = FakeRemote::default();
		remote.script("busy.example", Script::rcpt("bob@busy.example", reply));
		let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
		let bounces = Arc::new(MemorySink::new());
		let worker = worker
			.with_bounce_sink(bounces.clone())
			.with_suppression(SuppressionList::open(dir.path()).expect("suppression"))
			.with_delivery_log(DeliveryLog::open(dir.path(), 30));
		worker.pass().await.expect("pass");
		let records = DeliveryLog::open(dir.path(), 30)
			.list(None, |_| true)
			.expect("records");
		assert_eq!(records.len(), 1, "{reply}");
		let record = &records[0];
		assert_eq!(
			record.outcome,
			if permanent {
				DeliveryOutcome::Failed
			} else {
				DeliveryOutcome::Deferred
			}
		);
		assert_eq!(
			record.reply.as_deref(),
			Some(format!("{reply}; cause: {}", cause.sentence()).as_str())
		);
		assert_eq!(bounces.messages().len(), usize::from(permanent));
		let suppression = SuppressionList::open(dir.path()).expect("suppression");
		assert!(!suppression.is_suppressed("bob@busy.example"));
		assert!(!suppression.is_suppressed_for("alice@sender.example", "bob@busy.example"));
		if permanent {
			assert!(worker.spool.list().expect("list").is_empty());
			let body = String::from_utf8_lossy(&bounces.messages()[0].data).into_owned();
			assert!(body.contains(&format!("Diagnostic-Code: smtp; {reply}\r\n")));
		} else {
			let id = worker.spool.list().expect("list")[0];
			let state = worker
				.spool
				.load_envelope(id)
				.expect("envelope")
				.recipient_state("bob@busy.example");
			assert_eq!(state.status, RecipientStatus::Pending);
			assert_eq!(state.next_attempt, now + 600);
			assert_eq!(state.attempts, 1);
			assert_eq!(
				hold(&worker, &Destination::domain("busy.example"), now)
					.expect("hold")
					.until,
				now + 600
			);
		}
	}
}

#[test]
fn a_long_multibyte_reply_cannot_hide_or_truncate_the_cause() {
	for head in ["550 5.7.515", "550 5.7.26", "421 4.7.28", "550 5.7.1 IP"] {
		let reason = format!("{head} {}", "é".repeat(300));
		let logged = Worker::bounded_reply(&reason);
		assert!(logged.len() <= 200);
		assert!(logged.starts_with(head));
		assert!(logged.ends_with(provider_cause(&reason).expect("cause").sentence()));
	}
	let reason = format!("421 {} [TSS04]", "é".repeat(300));
	let logged = Worker::bounded_reply(&reason);
	assert!(logged.len() <= 200);
	assert!(logged.ends_with(ProviderCause::YahooThrottle.sentence()));
}

#[tokio::test]
async fn unknown_codes_and_generic_policy_keep_their_original_log_reply() {
	for reply in [
		"550 5.7.999 strange code",
		"550 5.7.1 policy rejected",
		"450 4.9.99 strange code",
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let remote = FakeRemote::default();
		remote.script("busy.example", Script::rcpt("bob@busy.example", reply));
		let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
		let worker = worker.with_delivery_log(DeliveryLog::open(dir.path(), 30));
		worker.pass().await.expect("pass");
		let records = DeliveryLog::open(dir.path(), 30)
			.list(None, |_| true)
			.expect("records");
		assert_eq!(records[0].reply.as_deref(), Some(reply));
		assert_eq!(
			records[0].outcome,
			if reply.starts_with('5') {
				DeliveryOutcome::Failed
			} else {
				DeliveryOutcome::Deferred
			}
		);
		assert!(hold(&worker, &Destination::domain("busy.example"), now).is_none());
	}
}

#[tokio::test]
async fn a_553_policy_bounces_once_without_suppressing_a_valid_recipient() {
	for (reply, suppress) in [
		("553 policy rejection: SPF required", false),
		("553 sender IP is on a list", false),
		("553 mailbox name not allowed", false),
		("553 no such user", true),
		("553 mailbox does not exist", true),
		("553 mailbox name not allowed for this user", true),
		("553 5.7.26 no such user", false),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let remote = FakeRemote::default();
		remote.script("busy.example", Script::rcpt("bob@busy.example", reply));
		let (worker, _) = worker_for(dir.path(), &["bob@busy.example"], &remote);
		let bounces = Arc::new(MemorySink::new());
		let worker = worker
			.with_bounce_sink(bounces.clone())
			.with_suppression(SuppressionList::open(dir.path()).expect("suppression"));
		worker.pass().await.expect("pass");
		worker.pass().await.expect("second pass");
		assert!(worker.spool.list().expect("list").is_empty());
		assert_eq!(bounces.messages().len(), 1, "{reply}");
		let list = SuppressionList::open(dir.path()).expect("suppression");
		assert!(
			!list.is_suppressed("bob@busy.example"),
			"a bounce does not suppress for every sender by default: {reply}"
		);
		assert_eq!(
			list.is_suppressed_for("alice@sender.example", "bob@busy.example"),
			suppress,
			"{reply}"
		);
	}
}

mod pauses;
