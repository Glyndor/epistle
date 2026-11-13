//! Listing the delivery log, the classes it keeps, and concurrent writers.

use super::base::{log_root, sample_record};
use super::*;
use std::collections::BTreeMap;

#[test]
fn list_streams_records_newest_day_first_and_respects_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	for (day, count) in [
		(1_700_000_000u64, 3u32),
		(1_700_086_400, 2),
		(1_700_172_800, 1),
	] {
		for offset in 0..count {
			log.append(&sample_record(
				day + u64::from(offset),
				&format!("r{day}-{offset}@elsewhere.example"),
				DeliveryOutcome::Delivered,
			))
			.expect("append");
		}
	}
	let all = log.list(None, |_| true).expect("list");
	assert_eq!(all.len(), 6, "every record across the three day files");
	// Newest day first; oldest day last.
	assert!(all[0].recipient.starts_with("r1700172800"));
	assert!(all[5].recipient.starts_with("r1700000000"));

	let one = log.list(Some(1), |_| true).expect("list with cap");
	assert_eq!(
		one.len(),
		1,
		"the cap stops the scan after the first record"
	);
	assert!(one[0].recipient.starts_with("r1700172800"));
}

#[test]
fn list_filter_drops_records_that_do_not_match() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	for (i, recipient) in ["a", "b", "a", "c"].iter().enumerate() {
		log.append(&sample_record(
			1_700_000_000 + i as u64,
			&format!("{recipient}@elsewhere.example"),
			DeliveryOutcome::Delivered,
		))
		.expect("append");
	}
	let only_a = log
		.list(None, |record| record.recipient.starts_with("a@"))
		.expect("list");
	assert_eq!(only_a.len(), 2);
	assert!(
		only_a
			.iter()
			.all(|record| record.recipient.starts_with("a@"))
	);
}

#[test]
fn list_returns_empty_when_the_log_directory_is_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let records = log.list(None, |_| true).expect("list");
	assert!(records.is_empty());
}

#[test]
fn the_class_is_kept_and_personal_is_left_out_of_the_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let now = now_epoch();
	let mut record = DeliveryRecord {
		time: now,
		spool_id: Uuid::now_v7(),
		account: Some("notices".into()),
		from: "notices@example.org".into(),
		recipient: "student@example.net".into(),
		outcome: DeliveryOutcome::Delivered,
		remote: None,
		reply: None,
		attempt: 1,
		extra: BTreeMap::new(),
		class: crate::evidence::MailClass::Transactional,
	};
	log.append(&record).expect("append");
	record.class = crate::evidence::MailClass::Personal;
	log.append(&record).expect("append");
	let text = std::fs::read_to_string(log.path_for_day(date_for_epoch(now)).expect("path"))
		.expect("read");
	let lines: Vec<&str> = text.lines().collect();
	assert!(lines[0].contains("\"class\":\"transactional\""));
	assert!(
		!lines[1].contains("\"class\""),
		"personal is the default and not written"
	);
	let back = log.list(None, |_| true).expect("list");
	assert_eq!(back.len(), 2);
	assert!(
		back.iter()
			.any(|r| r.class == crate::evidence::MailClass::Transactional)
	);
}

#[test]
fn writers_at_the_same_time_never_cut_each_others_lines() {
	let dir = tempfile::tempdir().expect("tempdir");
	let day = 1_700_000_000u64;
	let root = dir.path().to_path_buf();
	let handles: Vec<_> = (0..8)
		.map(|writer| {
			let root = root.clone();
			std::thread::spawn(move || {
				// Each writer opens the log itself, as the queue worker, the
				// cancel handler and the CLI do.
				let log = DeliveryLog::open(&root, 30);
				for n in 0..100 {
					let recipient = format!("writer{writer}-{n}@elsewhere.example");
					log.append(&sample_record(day, &recipient, DeliveryOutcome::Delivered))
						.expect("append");
				}
			})
		})
		.collect();
	for handle in handles {
		handle.join().expect("writer");
	}
	let body =
		std::fs::read_to_string(log_root(dir.path()).join("2023-11-14.jsonl")).expect("file");
	let lines: Vec<&str> = body.lines().collect();
	assert_eq!(lines.len(), 800);
	for line in lines {
		serde_json::from_str::<serde_json::Value>(line)
			.unwrap_or_else(|error| panic!("a cut line: {error}: {line:?}"));
	}
}
