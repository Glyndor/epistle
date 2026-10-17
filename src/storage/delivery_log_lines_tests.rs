//! The bounded line reader and the day window.

use std::io::Cursor;

use super::{Line, day_in_window, read_capped_line};

fn read_all(text: &[u8], cap: usize) -> Vec<(Line, String)> {
	let mut reader = Cursor::new(text.to_vec());
	let mut line = Vec::new();
	let mut found = Vec::new();
	loop {
		let kind = read_capped_line(&mut reader, &mut line, cap).unwrap();
		if kind == Line::End {
			return found;
		}
		found.push((kind, String::from_utf8_lossy(&line).into_owned()));
	}
}

#[test]
fn lines_are_read_one_by_one_and_the_last_may_lack_its_ending() {
	assert_eq!(
		read_all(b"one\n\ntwo\nthree", 100),
		vec![
			(Line::Read, "one".into()),
			(Line::Read, String::new()),
			(Line::Read, "two".into()),
			(Line::Read, "three".into()),
		]
	);
	assert!(read_all(b"", 100).is_empty());
}

#[test]
fn a_line_over_the_cap_is_dropped_and_the_next_one_still_read() {
	assert_eq!(
		read_all(b"0123456789\nok\n", 5),
		vec![(Line::TooLong, String::new()), (Line::Read, "ok".into())]
	);
	assert_eq!(read_all(b"01234\n", 5), vec![(Line::Read, "01234".into())]);
	assert_eq!(read_all(b"012345", 5), vec![(Line::TooLong, String::new())]);
}

#[test]
fn a_line_longer_than_the_reader_buffer_is_still_bounded() {
	let reader = std::io::BufReader::with_capacity(
		8,
		Cursor::new(b"aaaaaaaaaaaaaaaaaaaaaaaa\nz\n".to_vec()),
	);
	let mut reader = reader;
	let mut line = Vec::new();
	assert_eq!(
		read_capped_line(&mut reader, &mut line, 10).unwrap(),
		Line::TooLong
	);
	assert!(line.capacity() < 100);
	assert_eq!(
		read_capped_line(&mut reader, &mut line, 10).unwrap(),
		Line::Read
	);
	assert_eq!(line, b"z");
}

#[test]
fn only_the_days_in_the_window_are_opened() {
	let name = "2023-11-14.jsonl";
	assert!(day_in_window(name, None, None));
	assert!(day_in_window(name, Some("2023-11-14"), Some("2023-11-14")));
	assert!(!day_in_window(name, Some("2023-11-15"), None));
	assert!(!day_in_window(name, None, Some("2023-11-13")));
	assert!(day_in_window("notes.jsonl.bak", Some("2024-01-01"), None));
}

fn record(time: u64) -> crate::storage::DeliveryRecord {
	crate::storage::DeliveryRecord {
		time,
		spool_id: uuid::Uuid::from_u128(u128::from(time)),
		account: None,
		from: "a@example.org".into(),
		recipient: "b@remote.example".into(),
		outcome: crate::storage::DeliveryOutcome::Delivered,
		remote: None,
		reply: None,
		attempt: 1,
		extra: Default::default(),
	}
}

#[test]
fn list_between_does_not_open_days_outside_the_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = crate::storage::DeliveryLog::open(dir.path(), 30);
	// 2023-11-13, 2023-11-14 and 2023-11-15 at noon UTC.
	for time in [1_699_876_800, 1_699_963_200, 1_700_049_600] {
		log.append(&record(time)).expect("append");
	}
	let mut seen = Vec::new();
	let found = log
		.list_between(None, (Some(1_699_963_200), Some(1_699_963_200)), |record| {
			seen.push(record.time);
			true
		})
		.expect("list");
	assert_eq!(
		seen,
		vec![1_699_963_200],
		"only the day in the window is read"
	);
	assert_eq!(found.len(), 1);
	let mut all = 0;
	log.list_between(None, (None, None), |_| {
		all += 1;
		true
	})
	.expect("list");
	assert_eq!(all, 3);
}
