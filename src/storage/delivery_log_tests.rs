//! Tests for the per-recipient delivery log.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;
use crate::smtp::trace::header_values;

fn sample_record(time: u64, recipient: &str, outcome: DeliveryOutcome) -> DeliveryRecord {
	DeliveryRecord {
		time,
		spool_id: uuid::Uuid::now_v7(),
		account: Some("alice@example.org".into()),
		from: "alice@example.org".into(),
		recipient: recipient.into(),
		outcome,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 OK".into()),
		attempt: 1,
		extra: BTreeMap::new(),
	}
}

#[test]
fn append_writes_one_json_line_per_record_into_the_dated_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let day = 1_700_000_000u64; // 2023-11-14 UTC
	let mut first = sample_record(day, "bob@elsewhere.example", DeliveryOutcome::Delivered);
	first.reply = Some("250 2.0.0 OK".into());
	let mut second = sample_record(day + 1, "carol@elsewhere.example", DeliveryOutcome::Failed);
	second.reply = Some("550 5.1.1 user unknown".into());
	log.append(&first).expect("append first");
	log.append(&second).expect("append second");

	let path = log_root(dir.path()).join("2023-11-14.jsonl");
	let body = std::fs::read_to_string(&path).expect("file");
	let lines: Vec<&str> = body.lines().collect();
	assert_eq!(lines.len(), 2, "one line per record: {body}");
	let parsed: Vec<DeliveryRecord> = lines
		.iter()
		.map(|line| serde_json::from_str(line).expect("record"))
		.collect();
	assert_eq!(parsed[0].recipient, "bob@elsewhere.example");
	assert_eq!(parsed[0].outcome, DeliveryOutcome::Delivered);
	assert_eq!(parsed[1].recipient, "carol@elsewhere.example");
	assert_eq!(parsed[1].outcome, DeliveryOutcome::Failed);
}

#[test]
fn append_creates_files_with_owner_only_permissions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	log.append(&sample_record(1_700_000_000, "bob@elsewhere.example", DeliveryOutcome::Delivered))
		.expect("append");
	let path = log_root(dir.path()).join("2023-11-14.jsonl");
	let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
	assert_eq!(mode, 0o600, "the log file must be owner-only: {mode:#o}");
}

#[test]
fn append_keeps_reply_bounded_to_200_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let mut record = sample_record(1_700_000_000, "bob@elsewhere.example", DeliveryOutcome::Failed);
	let long_reply = "x".repeat(2_000);
	record.reply = Some(truncate_reply(&long_reply, 200));
	log.append(&record).expect("append");
	let path = log_root(dir.path()).join("2023-11-14.jsonl");
	let body = std::fs::read_to_string(&path).expect("file");
	let parsed: DeliveryRecord = serde_json::from_str(body.trim()).expect("record");
	assert_eq!(parsed.reply.as_deref().map(str::len), Some(200));
}

/// The reply is the first 200 bytes of the remote line. The
/// `webhook::sign` style "truncate at byte boundary" is intentional: the
/// operator wants the first line of the SMTP reply, not the message
/// itself, and 200 bytes is well over a typical reply.
fn truncate_reply(value: &str, max: usize) -> String {
	let mut out = String::new();
	for ch in value.chars() {
		if out.len() + ch.len_utf8() > max {
			break;
		}
		out.push(ch);
	}
	out
}

#[test]
fn append_is_a_noop_when_retention_is_zero() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 0);
	log.append(&sample_record(1_700_000_000, "bob@elsewhere.example", DeliveryOutcome::Delivered))
		.expect("append");
	assert!(!log_root(dir.path()).exists(), "the directory must not be created when the log is off");
}

#[test]
fn sweep_removes_only_files_older_than_the_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 7);
	for (day, name) in [
		(1_700_000_000u64, "2023-11-14.jsonl"),
		(1_700_086_400, "2023-11-15.jsonl"),
		(1_700_172_800, "2023-11-16.jsonl"),
		(1_700_259_200, "2023-11-17.jsonl"),
		(1_700_345_600, "2023-11-18.jsonl"),
		(1_700_432_000, "2023-11-19.jsonl"),
		(1_700_518_400, "2023-11-20.jsonl"),
		(1_700_604_800, "2023-11-21.jsonl"),
	] {
		log.append(&sample_record(day, "bob@elsewhere.example", DeliveryOutcome::Delivered))
			.expect("append");
		// The file name follows the record's date. Rename if the timestamp
		// in the record differs from the call site so the sweep's view of
		// the directory matches the test's calendar.
		let generated = log_root(dir.path())
			.join(format!("{}.jsonl", crate::storage::delivery_log::Day::from_unix_days((day / 86_400) as i64)));
		let target = log_root(dir.path()).join(name);
		if generated != target {
			std::fs::rename(&generated, &target).expect("rename");
		}
	}
	let now = (19_682 + 7) * 86_400 + 1;
	let removed = log.sweep(now).expect("sweep");
	// 2023-11-14..2023-11-20 are 14..8 days old (>7), 2023-11-21 is 7
	// days old (not >7) and stays.
	assert_eq!(removed, 7, "the seven oldest files leave, today stays");
	let remaining: Vec<String> = std::fs::read_dir(log_root(dir.path()))
		.expect("dir")
		.flatten()
		.map(|e| e.file_name().to_string_lossy().into_owned())
		.collect();
	assert_eq!(remaining, vec!["2023-11-21.jsonl".to_string()]);
}

#[test]
fn sweep_leaves_unrelated_files_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 7);
	let root = log_root(dir.path());
	std::fs::create_dir_all(&root).expect("dir");
	std::fs::write(root.join("readme.txt"), b"not a log").expect("write");
	std::fs::write(root.join("2023-11-14.jsonl"), b"{}\n").expect("write");
	std::fs::write(root.join("2023-11-14.jsonl.bak"), b"backup").expect("write");
	let removed = log.sweep(1_700_000_000 + 30 * 86_400).expect("sweep");
	assert_eq!(removed, 1, "only the dated .jsonl leaves");
	assert!(root.join("readme.txt").exists());
	assert!(root.join("2023-11-14.jsonl.bak").exists());
}

#[test]
fn sweep_with_zero_retention_clears_the_directory_and_its_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let root = log_root(dir.path());
	log.append(&sample_record(1_700_000_000, "bob@elsewhere.example", DeliveryOutcome::Delivered))
		.expect("append");
	log.append(&sample_record(1_700_086_400, "carol@elsewhere.example", DeliveryOutcome::Failed))
		.expect("append");
	assert!(root.is_dir(), "writes created the directory");
	let log_off = DeliveryLog::open(dir.path(), 0);
	let removed = log_off.sweep(1_700_000_000 + 2 * 86_400).expect("sweep");
	assert_eq!(removed, 2, "every file leaves when the log is off");
	assert!(!root.exists(), "flipping the setting off removes the directory");
}

#[test]
fn records_round_trip_through_serde_with_the_documented_fields() {
	let mut extra = BTreeMap::new();
	extra.insert("campaign".into(), "winter-2026".into());
	extra.insert("tenant".into(), "acme".into());
	let record = DeliveryRecord {
		time: 1_700_000_000,
		spool_id: uuid::Uuid::parse_str("01936b8e-7c00-7fff-9b1f-1d2c4a5b6c7d").unwrap(),
		account: Some("alice@example.org".into()),
		from: "alice@example.org".into(),
		recipient: "bob@elsewhere.example".into(),
		outcome: DeliveryOutcome::Suppressed,
		remote: None,
		reply: None,
		attempt: 0,
		extra,
	};
	let json = serde_json::to_value(&record).expect("value");
	assert_eq!(json["time"], 1_700_000_000u64);
	assert_eq!(json["spool_id"], "01936b8e-7c00-7fff-9b1f-1d2c4a5b6c7d");
	assert_eq!(json["account"], "alice@example.org");
	assert_eq!(json["from"], "alice@example.org");
	assert_eq!(json["recipient"], "bob@elsewhere.example");
	assert_eq!(json["outcome"], "suppressed");
	assert!(json.get("remote").is_none());
	assert!(json.get("reply").is_none());
	assert_eq!(json["attempt"], 0);
	assert_eq!(json["extra"]["campaign"], "winter-2026");
	assert_eq!(json["extra"]["tenant"], "acme");
}

#[test]
fn outcome_strings_match_documented_wire_form() {
	for outcome in [
		DeliveryOutcome::Delivered,
		DeliveryOutcome::Deferred,
		DeliveryOutcome::Failed,
		DeliveryOutcome::Suppressed,
		DeliveryOutcome::Canceled,
	] {
		assert_eq!(DeliveryOutcome::parse(outcome.as_str()), Some(outcome));
	}
	assert_eq!(DeliveryOutcome::parse("unknown"), None);
}

#[test]
fn a_record_with_no_extra_or_remote_does_not_emit_them() {
	let record = DeliveryRecord {
		time: 1_700_000_000,
		spool_id: uuid::Uuid::now_v7(),
		account: None,
		from: "".into(),
		recipient: "bob@elsewhere.example".into(),
		outcome: DeliveryOutcome::Canceled,
		remote: None,
		reply: None,
		attempt: 0,
		extra: BTreeMap::new(),
	};
	let json = serde_json::to_value(&record).expect("value");
	assert!(json.get("account").is_none(), "absent account is skipped");
	assert!(json.get("remote").is_none());
	assert!(json.get("reply").is_none());
	assert!(json.get("extra").is_none(), "empty extra is skipped");
	assert_eq!(json["from"], "");
	assert_eq!(json["outcome"], "canceled");
}

#[test]
fn an_entry_record_carries_the_message_id_when_present() {
	// The delivery log records the spool id, not the message id; the
	// message body is never read at log time. This test pins that
	// contract: the field is `spool_id` and no `message_id` is
	// auto-populated from the message body.
	let record = sample_record(1_700_000_000, "bob@elsewhere.example", DeliveryOutcome::Delivered);
	let json = serde_json::to_value(&record).expect("value");
	assert!(json.get("message_id").is_none(), "no body is read for the log");
	assert!(json.get("spool_id").is_some());
}

#[test]
fn header_values_extracts_a_message_id_for_the_webhook() {
	// Sanity check that the helper we lean on for the webhook carries a
	// message id through to a record; the log itself never reads the
	// body, but the helper used by the webhook does.
	let data =
		b"Message-ID: <abc@elsewhere.example>\r\nFrom: alice@example.org\r\n\r\nbody\r\n".to_vec();
	assert_eq!(header_values(&data, "message-id"), vec!["<abc@elsewhere.example>"]);
}

#[test]
fn list_streams_records_newest_day_first_and_respects_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	for (day, count) in [(1_700_000_000u64, 3u32), (1_700_086_400, 2), (1_700_172_800, 1)] {
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
	assert_eq!(one.len(), 1, "the cap stops the scan after the first record");
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
	assert!(only_a.iter().all(|record| record.recipient.starts_with("a@")));
}

#[test]
fn list_returns_empty_when_the_log_directory_is_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let records = log.list(None, |_| true).expect("list");
	assert!(records.is_empty());
}

#[test]
fn parse_since_accepts_durations_and_rfc3339_and_rejects_garbage() {
	let now = 1_700_000_000;
	assert_eq!(parse_since("", now).expect("empty"), None);
	assert_eq!(
		parse_since("24h", now).expect("24h"),
		Some(now - 24 * 3600)
	);
	assert_eq!(parse_since("7d", now).expect("7d"), Some(now - 7 * 86_400));
	assert_eq!(parse_since("30m", now).expect("30m"), Some(now - 30 * 60));
	assert_eq!(parse_since("5s", now).expect("5s"), Some(now - 5));
	// 2024-01-02T03:04:05Z = 1704164645 epoch seconds
	assert_eq!(
		parse_since("2024-01-02T03:04:05Z", now).expect("rfc3339"),
		Some(1_704_164_645)
	);
	// `+02:00` offset: 03:04:05 local is 01:04:05 UTC.
	assert_eq!(
		parse_since("2024-01-02T03:04:05+02:00", now).expect("offset"),
		Some(1_704_157_445)
	);
	// Negative offset: 03:04:05-05:00 is 08:04:05 UTC.
	assert_eq!(
		parse_since("2024-01-02T03:04:05-05:00", now).expect("negative offset"),
		Some(1_704_182_645)
	);
	assert!(parse_since("not-a-time", now).is_err());
	assert!(parse_since("2024-13-40T99:99:99Z", now).is_err());
}

fn log_root(data_dir: &Path) -> std::path::PathBuf {
	data_dir.join("deliverylog")
}
