use super::*;
use crate::evidence::test_support::{accepted, delivered};

#[test]
fn hex_round_trips_and_refuses_anything_else() {
	let hash = sha256(b"evidence");
	assert_eq!(hash_from_hex(&to_hex(&hash)), Some(hash));
	assert_eq!(hash_from_hex(&to_hex(&hash).to_uppercase()), None);
	assert_eq!(hash_from_hex("00"), None);
	assert_eq!(hash_from_hex(&"g".repeat(64)), None);
	assert_eq!(to_hex(&[0x00, 0xff, 0x1a]), "00ff1a");
}

#[test]
fn a_record_is_one_json_line_with_its_kind() {
	let record = Record {
		v: FORMAT_VERSION,
		prev: to_hex(&GENESIS),
		time: 1,
		entry: accepted(7),
	};
	let line = record.to_line().expect("line");
	assert!(!line.contains(&b'\n'), "a record is a single line");
	let text = String::from_utf8(line.clone()).expect("utf8");
	assert!(text.starts_with("{\"v\":1,\"prev\":\"0000"), "{text}");
	assert!(text.contains("\"kind\":\"accepted\""), "{text}");
	assert!(text.contains("\"class\":\"transactional\""), "{text}");
	let back: Record = serde_json::from_slice(&line).expect("parse");
	assert_eq!(back, record);
}

#[test]
fn retention_and_ids_come_from_the_entry() {
	assert_eq!(accepted(1).retain_days(), 365);
	assert_eq!(delivered(1).retain_days(), 365);
	let setting = Entry::Setting(Setting {
		name: "timestamp".into(),
		value: "disabled".into(),
	});
	assert_eq!(setting.retain_days(), 0);
	assert_eq!(setting.spool_id(), None);
	assert_eq!(delivered(3).spool_id(), Some(Uuid::from_u128(3)));
}

#[test]
fn bounded_cuts_on_a_character_boundary() {
	let long = "ñ".repeat(MAX_FIELD);
	let cut = bounded(&long);
	assert!(cut.len() <= MAX_FIELD);
	assert_eq!(cut.len(), MAX_FIELD - MAX_FIELD % 2);
	assert_eq!(bounded("short"), "short");
}
