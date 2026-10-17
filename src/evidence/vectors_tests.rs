//! The bytes written for each kind of record, checkpoint and statement are
//! pinned. A hash chain is only as old as its encoding: a field moved, a
//! name changed or a serializer that spaces differently makes every line
//! already written "malformed", so the lines below must not change by
//! accident. Change one, and every deployed log needs a new format version.

use uuid::Uuid;

use super::MailClass;
use super::ack::Acknowledged;
use super::checkpoint::Checkpoint;
use super::record::{
	Abandoned, Accepted, Entry, Outcome, OutcomeKind, Purge, Record, Retention, RetentionMode,
	Setting, TlsSummary,
};
use super::retention::{PurgedDay, Statement};
use super::rotation::Rotation;

fn hex(n: u8) -> String {
	format!("{n:02x}").repeat(32)
}

fn line(entry: Entry) -> String {
	let record = Record {
		v: 1,
		seq: 7,
		prev: hex(1),
		time: 1_791_000_000,
		entry,
	};
	String::from_utf8(record.to_line().expect("line")).expect("utf8")
}

fn id() -> Uuid {
	Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)
}

fn samples() -> Vec<(&'static str, String)> {
	let accepted = Entry::Accepted(Accepted {
		spool_id: id(),
		account: "notices".into(),
		tenant: Some("school".into()),
		class: MailClass::Transactional,
		from: "notices@example.org".into(),
		recipients: vec!["a@example.net".into(), "b@example.net".into()],
		message_id: Some("<1@example.org>".into()),
		date: Some("Wed, 14 Oct 2026 10:00:00 +0000".into()),
		subject: Some("Notice".into()),
		sha256: hex(2),
		size: 1234,
		retention: Retention {
			mode: RetentionMode::Full,
			days: 365,
		},
	});
	let outcome = Entry::Outcome(Outcome {
		spool_id: id(),
		class: MailClass::Transactional,
		recipient: "a@example.net".into(),
		result: OutcomeKind::Delivered,
		attempt: 2,
		remote: Some("mx.example.net".into()),
		reply: Some("250 2.0.0 OK".into()),
		tls: Some(TlsSummary {
			version: "TLSv1_3".into(),
			cipher: "TLS13_AES_256_GCM_SHA384".into(),
		}),
		dane: true,
		mta_sts: Some("enforce".into()),
		retain_days: 365,
	});
	let abandoned = Entry::Abandoned(Abandoned {
		spool_id: id(),
		reason: "the server stopped before the message was queued".into(),
		retain_days: 365,
		recipients: Vec::new(),
	});
	let purge = Entry::Purge(Purge {
		from: "2026-10-12".into(),
		through: "2026-10-14".into(),
		records: 3,
		last_hash: hex(3),
		checkpoint: hex(4),
		statement: hex(5),
	});
	let setting = Entry::Setting(Setting {
		name: "timestamp".into(),
		value: "enabled".into(),
	});
	let acknowledged = Entry::Acknowledged(Acknowledged {
		break_day: "2026-10-14".into(),
		break_line: 3,
		break_id: hex(6),
		reason: "restored".into(),
		operator: "uid=0 host=mail".into(),
		key: hex(7),
		state: String::new(),
		signature: "ab".repeat(64),
	});
	let rotated = Entry::KeyRotated(Rotation {
		old: hex(8),
		new: hex(9),
		day: "2026-10-17".into(),
		signature: "cd".repeat(64),
	});
	let checkpoint = serde_json::to_string_pretty(&Checkpoint {
		v: 1,
		day: "2026-10-14".into(),
		records: 3,
		merkle_root: hex(10),
		first_prev: hex(11),
		last_hash: hex(12),
		last_seq: 9,
		last_time: 1_791_000_000,
		prev_checkpoint: Some(hex(13)),
		retain_until: "2027-10-14".into(),
		timestamp: "enabled".into(),
		key: hex(14),
		created: 1_791_000_100,
	})
	.expect("checkpoint");
	let statement = serde_json::to_string_pretty(&Statement {
		v: 1,
		from: "2026-10-12".into(),
		through: "2026-10-14".into(),
		records: 3,
		days: vec![PurgedDay {
			day: "2026-10-12".into(),
			records: 3,
			merkle_root: hex(15),
			checkpoint: hex(16),
		}],
		last_hash: hex(17),
		last_seq: 9,
		last_time: 1_791_000_000,
		checkpoint: hex(18),
		retain_until: "2027-10-14".into(),
		time: 1_791_000_200,
		key: hex(19),
	})
	.expect("statement");
	vec![
		("accepted", line(accepted)),
		("outcome", line(outcome)),
		("abandoned", line(abandoned)),
		("purge", line(purge)),
		("setting", line(setting)),
		("acknowledged", line(acknowledged)),
		("key_rotated", line(rotated)),
		("checkpoint", checkpoint),
		("statement", statement),
	]
}

const ACCEPTED: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"accepted","spool_id":"01234567-89ab-cdef-0123-456789abcdef","account":"notices","tenant":"school","class":"transactional","from":"notices@example.org","recipients":["a@example.net","b@example.net"],"message_id":"<1@example.org>","date":"Wed, 14 Oct 2026 10:00:00 +0000","subject":"Notice","sha256":"0202020202020202020202020202020202020202020202020202020202020202","size":1234,"retention":{"mode":"full","days":365}}"#;

const OUTCOME: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"outcome","spool_id":"01234567-89ab-cdef-0123-456789abcdef","class":"transactional","recipient":"a@example.net","result":"delivered","attempt":2,"remote":"mx.example.net","reply":"250 2.0.0 OK","tls":{"version":"TLSv1_3","cipher":"TLS13_AES_256_GCM_SHA384"},"dane":true,"mta_sts":"enforce","retain_days":365}"#;

const ABANDONED: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"abandoned","spool_id":"01234567-89ab-cdef-0123-456789abcdef","reason":"the server stopped before the message was queued","retain_days":365}"#;

const PURGE: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"purge","from":"2026-10-12","through":"2026-10-14","records":3,"last_hash":"0303030303030303030303030303030303030303030303030303030303030303","checkpoint":"0404040404040404040404040404040404040404040404040404040404040404","statement":"0505050505050505050505050505050505050505050505050505050505050505"}"#;

const SETTING: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"setting","name":"timestamp","value":"enabled"}"#;

const ACKNOWLEDGED: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"acknowledged","break_day":"2026-10-14","break_line":3,"break_id":"0606060606060606060606060606060606060606060606060606060606060606","reason":"restored","operator":"uid=0 host=mail","key":"0707070707070707070707070707070707070707070707070707070707070707","signature":"abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab"}"#;

const KEY_ROTATED: &str = r#"{"v":1,"seq":7,"prev":"0101010101010101010101010101010101010101010101010101010101010101","time":1791000000,"kind":"key_rotated","old":"0808080808080808080808080808080808080808080808080808080808080808","new":"0909090909090909090909090909090909090909090909090909090909090909","day":"2026-10-17","signature":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}"#;

const CHECKPOINT: &str = r#"{
  "v": 1,
  "day": "2026-10-14",
  "records": 3,
  "merkle_root": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
  "first_prev": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
  "last_hash": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
  "last_seq": 9,
  "last_time": 1791000000,
  "prev_checkpoint": "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
  "retain_until": "2027-10-14",
  "timestamp": "enabled",
  "key": "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
  "created": 1791000100
}"#;

const STATEMENT: &str = r#"{
  "v": 1,
  "from": "2026-10-12",
  "through": "2026-10-14",
  "records": 3,
  "days": [
    {
      "day": "2026-10-12",
      "records": 3,
      "merkle_root": "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      "checkpoint": "1010101010101010101010101010101010101010101010101010101010101010"
    }
  ],
  "last_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "last_seq": 9,
  "last_time": 1791000000,
  "checkpoint": "1212121212121212121212121212121212121212121212121212121212121212",
  "retain_until": "2027-10-14",
  "time": 1791000200,
  "key": "1313131313131313131313131313131313131313131313131313131313131313"
}"#;

#[test]
fn every_kind_is_written_as_pinned() {
	let written: std::collections::BTreeMap<_, _> = samples().into_iter().collect();
	let pinned = [
		("accepted", ACCEPTED),
		("outcome", OUTCOME),
		("abandoned", ABANDONED),
		("purge", PURGE),
		("setting", SETTING),
		("acknowledged", ACKNOWLEDGED),
		("key_rotated", KEY_ROTATED),
		("checkpoint", CHECKPOINT),
		("statement", STATEMENT),
	];
	assert_eq!(written.len(), pinned.len());
	for (name, expected) in pinned {
		assert_eq!(written[name], expected, "{name} is written differently");
	}
}

#[test]
fn every_pinned_line_is_read_back_as_the_record_it_was_made_from() {
	for (name, text) in samples() {
		if name == "checkpoint" || name == "statement" {
			continue;
		}
		let record =
			Record::parse_canonical(text.as_bytes()).unwrap_or_else(|why| panic!("{name}: {why}"));
		assert_eq!(
			String::from_utf8(record.to_line().expect("line")).expect("utf8"),
			text,
			"{name}"
		);
	}
}
