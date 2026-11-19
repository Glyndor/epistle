//! The delivery result, read from the log and put in plain language.

use std::time::Duration;

use uuid::Uuid;

use crate::cli::deliverability::delivery::{await_result, explain_reply};
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

const T: u64 = 1_800_000_000;

fn record(id: Uuid, outcome: DeliveryOutcome, reply: Option<&str>, time: u64) -> DeliveryRecord {
	DeliveryRecord {
		time,
		spool_id: id,
		account: Some("alice".into()),
		from: "alice@example.org".into(),
		recipient: "check@mail-tester.example".into(),
		outcome,
		remote: Some("mx.mail-tester.example".into()),
		reply: reply.map(str::to_string),
		attempt: 1,
		extra: Default::default(),
		class: Default::default(),
	}
}

async fn result(
	records: &[DeliveryRecord],
	id: Uuid,
	days: u64,
) -> crate::cli::deliverability::delivery::Delivery {
	let dir = tempfile::tempdir().expect("dir");
	let log = DeliveryLog::open(dir.path(), 7);
	for record in records {
		log.append(record).expect("append");
	}
	await_result(&log, days, id, Duration::ZERO, Duration::from_millis(1)).await
}

#[tokio::test]
async fn a_delivered_message_says_what_acceptance_does_not_prove() {
	let id = Uuid::now_v7();
	let delivery = result(
		&[record(
			id,
			DeliveryOutcome::Delivered,
			Some("250 2.0.0 ok"),
			T,
		)],
		id,
		7,
	)
	.await;
	assert_eq!(delivery.state, "delivered");
	assert!(
		delivery
			.explanation
			.contains("not that it reached the inbox")
	);
	assert!(!delivery.is_failure());
}

#[tokio::test]
async fn a_refusal_by_policy_is_explained_with_its_enhanced_code() {
	let id = Uuid::now_v7();
	let reply = "550 5.7.26 This message does not have authentication information";
	let delivery = result(
		&[record(id, DeliveryOutcome::Failed, Some(reply), T)],
		id,
		7,
	)
	.await;
	assert_eq!(delivery.state, "failed");
	assert!(delivery.is_failure());
	assert!(
		delivery.explanation.contains("by policy"),
		"{}",
		delivery.explanation
	);
	assert!(
		delivery.explanation.contains("5.7.26"),
		"{}",
		delivery.explanation
	);
	assert!(
		delivery.explanation.contains("epistle verify-dns"),
		"{}",
		delivery.explanation
	);
}

#[tokio::test]
async fn a_missing_mailbox_is_told_apart_from_a_policy_refusal() {
	let text = explain_reply("550 5.1.1 no such user", true);
	assert!(text.contains("does not exist"), "{text}");
}

#[tokio::test]
async fn a_deferral_is_not_a_failure_and_keeps_its_reason() {
	let id = Uuid::now_v7();
	let reply = "451 4.7.1 greylisted, try later";
	let delivery = result(
		&[record(id, DeliveryOutcome::Deferred, Some(reply), T)],
		id,
		7,
	)
	.await;
	assert_eq!(delivery.state, "deferred");
	assert!(!delivery.is_failure());
}

#[tokio::test]
async fn no_record_yet_is_queued_and_names_the_command_to_read_it_later() {
	let id = Uuid::now_v7();
	let delivery = result(
		&[record(Uuid::now_v7(), DeliveryOutcome::Failed, None, T)],
		id,
		7,
	)
	.await;
	assert_eq!(delivery.state, "queued");
	assert!(delivery.explanation.contains(&id.to_string()));
	assert!(!delivery.is_failure());
}

#[tokio::test]
async fn the_newest_record_of_the_message_wins() {
	let id = Uuid::now_v7();
	let records = [
		record(id, DeliveryOutcome::Deferred, Some("451 4.7.1 later"), T),
		record(id, DeliveryOutcome::Delivered, Some("250 ok"), T + 60),
	];
	assert_eq!(result(&records, id, 7).await.state, "delivered");
}

#[tokio::test]
async fn a_log_that_is_off_says_so() {
	let id = Uuid::now_v7();
	let delivery = result(&[], id, 0).await;
	assert_eq!(delivery.state, "unlogged");
	assert!(delivery.explanation.contains("delivery_log_days"));
}

#[tokio::test]
async fn what_the_remote_wrote_is_escaped_before_it_reaches_a_terminal() {
	let id = Uuid::now_v7();
	let reply = "550 5.7.1 \u{1b}[2Jgone";
	let delivery = result(
		&[record(id, DeliveryOutcome::Failed, Some(reply), T)],
		id,
		7,
	)
	.await;
	let shown = delivery.reply.expect("reply");
	assert!(!shown.contains('\u{1b}'), "{shown:?}");
	assert!(shown.contains("\\u{1b}"), "{shown:?}");
}
