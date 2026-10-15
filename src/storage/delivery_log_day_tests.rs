use std::io::Write;

use super::*;
use crate::storage::DeliveryOutcome;

const DAY: i64 = 20_375;

fn record(time: u64, recipient: &str) -> DeliveryRecord {
	DeliveryRecord {
		time,
		spool_id: uuid::Uuid::nil(),
		account: None,
		from: "alice@sender.example".into(),
		recipient: recipient.into(),
		outcome: DeliveryOutcome::Delivered,
		remote: Some("mx.example.net".into()),
		reply: Some("250 OK".into()),
		attempt: 1,
		extra: Default::default(),
	}
}

fn recipients(log: &DeliveryLog, day: i64) -> (Vec<String>, u64) {
	let mut seen = Vec::new();
	let skipped = log
		.for_each_on_day(day, |record| seen.push(record.recipient.clone()))
		.expect("read the day");
	(seen, skipped)
}

#[test]
fn one_day_is_read_in_order_and_other_days_are_left_out() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let start = DAY as u64 * 86_400;
	log.append(&record(start - 1, "yesterday@example.net"))
		.expect("append");
	log.append(&record(start, "first@example.net"))
		.expect("append");
	log.append(&record(start + 86_399, "last@example.net"))
		.expect("append");
	log.append(&record(start + 86_400, "tomorrow@example.net"))
		.expect("append");
	assert_eq!(
		recipients(&log, DAY),
		(
			vec!["first@example.net".to_string(), "last@example.net".into()],
			0
		)
	);
	assert_eq!(day_name(DAY), "2025-10-14");
	assert_eq!(recipients(&log, DAY + 5), (Vec::new(), 0));
}

#[test]
fn an_overlong_or_broken_line_is_skipped_and_reading_goes_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let start = DAY as u64 * 86_400;
	log.append(&record(start, "before@example.net"))
		.expect("append");
	let path = dir.path().join("deliverylog").join("2025-10-14.jsonl");
	let mut file = std::fs::OpenOptions::new()
		.append(true)
		.open(&path)
		.expect("open the day");
	// Ten megabytes on one line, then a line that is not JSON.
	file.write_all(&vec![b'x'; 10 * 1024 * 1024])
		.expect("write");
	file.write_all(b"\n{not json\n\n").expect("write");
	drop(file);
	log.append(&record(start + 1, "after@example.net"))
		.expect("append");
	assert_eq!(
		recipients(&log, DAY),
		(
			vec!["before@example.net".to_string(), "after@example.net".into()],
			2
		)
	);
}

#[test]
fn a_line_at_the_limit_is_read_and_one_past_it_is_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let start = DAY as u64 * 86_400;
	let mut long = record(start, "long@example.net");
	let base = serde_json::to_vec(&long).expect("json").len();
	// A correlation value that brings the line to exactly the limit.
	long.extra.insert(
		"k".into(),
		"v".repeat(MAX_LINE - base - "\"k\":\"\"".len() - 11),
	);
	let mut line = serde_json::to_vec(&long).expect("json");
	assert_eq!(line.len(), MAX_LINE, "the record fills the limit");
	let mut over = long.clone();
	over.recipient = "over@example.net".into();
	over.extra.insert("k".into(), "v".repeat(MAX_LINE));
	std::fs::create_dir_all(dir.path().join("deliverylog")).expect("dir");
	line.push(b'\n');
	line.extend(serde_json::to_vec(&over).expect("json"));
	std::fs::write(
		dir.path().join("deliverylog").join("2025-10-14.jsonl"),
		line,
	)
	.expect("write");
	assert_eq!(
		recipients(&log, DAY),
		(vec!["long@example.net".to_string()], 1)
	);
}
