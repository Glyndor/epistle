//! The use the warm-up is for: one account sends a thousand important
//! notifications in one day from a new address. Every one must arrive,
//! once, with no bounce, no failure and no delay warning, however many
//! days the cap takes to let them all through.

use std::collections::BTreeMap;

use super::*;
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::queue::warmup::settings::{self, Settings};
use crate::queue::warmup::{Group, Warmup};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use crate::storage::{DeliveryLog, DeliveryOutcome, FsSpool};

const GMAIL_MX: &str = "gmail-smtp-in.l.google.com";

#[tokio::test]
async fn a_thousand_notifications_from_a_new_address_all_arrive_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.hosted("gmail.com", GMAIL_MX, Script::default());
	let recipients: Vec<String> = (0..1000).map(|n| format!("user{n}@gmail.com")).collect();
	let spool = FsSpool::open(dir.path()).expect("open spool");
	// Submitted at 06:00 UTC: the first day is three quarters of a day.
	let submitted = 20_375 * 86_400 + 6 * 3600;
	let id = uuid::Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, submitted, 0));
	spool
		.store_as(
			&AcceptedMessage {
				reverse_path: "notify@sender.example".into(),
				recipients: recipients.clone(),
				data: b"Subject: your notice\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
				sender_verified: false,
			},
			id,
			Some("notify"),
			&BTreeMap::new(),
		)
		.expect("store");
	let start = submitted + 1;
	let enabled = Settings {
		enabled: true,
		..Settings::default()
	};
	settings::save(dir.path(), &enabled).expect("settings");
	let log = DeliveryLog::open(dir.path(), 30);
	let warmup = Arc::new(Warmup::open(dir.path(), Some(log.clone()), start));
	let reports = Arc::new(MemorySink::new());
	let mut worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_delivery_log(log.clone())
		.with_warmup(Arc::clone(&warmup))
		.with_bounce_sink(reports.clone() as Arc<dyn MessageSink>);
	worker.set_jitter(|| 1.0);

	// The queue scans every half hour and the timer judges each day.
	let mut now = start;
	while now < start + 12 * 86_400 && !worker.spool.list().expect("list").is_empty() {
		worker.set_now(now);
		warmup.tick(now);
		worker.pass().await.expect("pass");
		now += 1800;
	}

	assert!(
		worker.spool.list().expect("list").is_empty(),
		"every notification left the queue"
	);
	let not_once: Vec<&String> = recipients
		.iter()
		.filter(|recipient| remote.copies(recipient) != 1)
		.collect();
	assert!(
		not_once.is_empty(),
		"not delivered exactly once: {not_once:?}"
	);
	assert_eq!(
		reports.messages().len(),
		0,
		"no bounce and no delay warning"
	);
	let records = log.list(None, |_| true).expect("log");
	assert_eq!(records.len(), 1000, "one record per notification");
	assert!(
		records
			.iter()
			.all(|record| record.outcome == DeliveryOutcome::Delivered),
		"nothing deferred, failed or expired"
	);
	// The account sent alone, so it used each day's whole cap (the first
	// day from 06:00, more than three quarters of 50), and every day went
	// well and grew it: the last notification left on the sixth day.
	warmup.tick(now + 86_400);
	let (_, state) = warmup.snapshot();
	let days: Vec<_> = state
		.group(Group::Gmail)
		.history
		.iter()
		.map(|record| (record.cap, record.sent, record.verdict.label()))
		.collect();
	assert_eq!(
		days,
		[
			(Some(50), 39, "good"),
			(Some(75), 75, "good"),
			(Some(113), 112, "good"),
			(Some(170), 170, "good"),
			(Some(255), 255, "good"),
			(Some(383), 349, "good"),
		]
	);
}
