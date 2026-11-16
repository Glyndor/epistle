use std::io::Cursor;

use super::super::merge::merge_readers;

fn merged(inputs: &[&str], cutting: bool) -> String {
	let readers: Vec<Cursor<Vec<u8>>> = inputs
		.iter()
		.map(|text| Cursor::new(text.as_bytes().to_vec()))
		.collect();
	let mut out = Vec::new();
	merge_readers(readers, cutting, &mut out).expect("merge");
	String::from_utf8(out).expect("utf-8")
}

#[test]
fn two_services_come_out_in_time_order() {
	let mail = "mail-1 | 2026-01-01T10:00:01Z m1\nmail-1 | 2026-01-01T10:00:04Z m2\n";
	let db = "db-1 | 2026-01-01T10:00:02Z d1\ndb-1 | 2026-01-01T10:00:03Z d2\n";
	assert_eq!(
		merged(&[mail, db], true),
		"mail-1 | 2026-01-01T10:00:01Z m1\n\
		 db-1 | 2026-01-01T10:00:02Z d1\n\
		 db-1 | 2026-01-01T10:00:03Z d2\n\
		 mail-1 | 2026-01-01T10:00:04Z m2\n"
	);
}

#[test]
fn the_same_second_keeps_the_order_of_the_services() {
	let a = "a-1 | 2026-01-01T10:00:00Z first\n";
	let b = "b-1 | 2026-01-01T10:00:00Z second\n";
	assert_eq!(merged(&[a, b], true), format!("{a}{b}"));
	assert_eq!(merged(&[b, a], true), format!("{b}{a}"));
}

#[test]
fn zones_are_compared_by_the_instant_not_the_text() {
	let east = "a-1 | 2026-01-01T10:00:00-05:00 later\n";
	let utc = "b-1 | 2026-01-01T12:00:00Z earlier\n";
	assert_eq!(merged(&[east, utc], true), format!("{utc}{east}"));
}

#[test]
fn a_line_without_a_time_stays_behind_the_line_it_continues() {
	let a = "a-1 | 2026-01-01T10:00:01Z boom\na-1 | 	at frame one\na-1 | 	at frame two\n";
	let b = "b-1 | 2026-01-01T10:00:02Z other\n";
	assert_eq!(
		merged(&[a, b], true),
		"a-1 | 2026-01-01T10:00:01Z boom\n\
		 a-1 | 	at frame one\n\
		 a-1 | 	at frame two\n\
		 b-1 | 2026-01-01T10:00:02Z other\n"
	);
}

#[test]
fn an_empty_service_does_not_stop_the_others() {
	let a = "a-1 | 2026-01-01T10:00:01Z only\n";
	assert_eq!(merged(&["", a, ""], true), a);
}

#[test]
fn a_long_line_is_cut_unless_raw() {
	let long = format!("a-1 | 2026-01-01T10:00:01Z {}\n", "q".repeat(600));
	assert!(merged(&[&long], true).contains("[100 more bytes cut; --raw shows them]"));
	assert_eq!(merged(&[&long], false), long);
}
