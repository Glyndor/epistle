//! Every field `walk_day` reads is checked, and two byte strings never
//! stand for one record.

use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Entry, FORMAT_VERSION};
use crate::evidence::test_support::{accepted, at, delivered};

const DAY: i64 = 20_740;

fn day_path(root: &Path) -> std::path::PathBuf {
	day_file(&root.join(CHAIN_DIR), Day(DAY))
}

fn line(seq: u64, prev: &str, time: u64, entry: Entry) -> Vec<u8> {
	Record {
		v: FORMAT_VERSION,
		seq,
		prev: prev.to_string(),
		time,
		entry,
	}
	.to_line()
	.expect("line")
}

fn write(root: &Path, lines: &[Vec<u8>]) {
	std::fs::create_dir_all(root.join(CHAIN_DIR)).expect("dir");
	let mut bytes = Vec::new();
	for line in lines {
		bytes.extend_from_slice(line);
		bytes.push(b'\n');
	}
	std::fs::write(day_path(root), bytes).expect("write");
}

fn first_break(root: &Path) -> String {
	walk_day(root, Day(DAY), Some(Position::START), |_, _, _| {})
		.expect_err("must not verify")
		.to_string()
}

fn zero() -> String {
	to_hex(&crate::evidence::record::GENESIS)
}

#[test]
fn a_field_the_format_does_not_know_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let good = line(1, &zero(), at(DAY, 1), accepted(1));
	let text = String::from_utf8(good).expect("utf8");
	let padded = text.replacen("{\"v\":1,", "{\"v\":1,\"note\":\"x\",", 1);
	write(dir.path(), &[padded.into_bytes()]);
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 1: not an evidence record (not in canonical form (unknown, duplicate or reordered fields))"
	);
}

#[test]
fn reordered_spacing_or_duplicate_fields_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let text = String::from_utf8(line(1, &zero(), at(DAY, 1), accepted(1))).expect("utf8");
	let spaced = text.replacen("{\"v\":1,", "{\"v\": 1,", 1);
	write(dir.path(), &[spaced.into_bytes()]);
	assert!(first_break(dir.path()).contains("not in canonical form"));
	let duplicated = text.replacen("{\"v\":1,", "{\"v\":1,\"v\":1,", 1);
	write(dir.path(), &[duplicated.into_bytes()]);
	assert!(
		first_break(dir.path()).contains("duplicate field"),
		"a duplicate key is named"
	);
}

#[test]
fn sequence_numbers_must_be_contiguous() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = line(1, &zero(), at(DAY, 1), accepted(1));
	let skipped = line(
		3,
		&to_hex(&crate::evidence::record::sha256(&first)),
		at(DAY, 2),
		delivered(1),
	);
	write(dir.path(), &[first, skipped]);
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 2: not an evidence record (sequence 3 follows 1)"
	);
}

#[test]
fn time_never_goes_backwards_and_stays_in_its_day() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = line(1, &zero(), at(DAY, 5), accepted(1));
	let earlier = line(
		2,
		&to_hex(&crate::evidence::record::sha256(&first)),
		at(DAY, 4),
		delivered(1),
	);
	write(dir.path(), &[first, earlier]);
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 2: not an evidence record (the time goes backwards)"
	);
	write(dir.path(), &[line(1, &zero(), at(DAY + 1, 1), accepted(1))]);
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 1: not an evidence record (the record's time is not in this day)"
	);
}

#[test]
fn an_empty_day_file_does_not_verify() {
	let dir = tempfile::tempdir().expect("tempdir");
	write(dir.path(), &[]);
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14: not an evidence record (empty day file)"
	);
}

#[test]
fn a_symlinked_day_file_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let elsewhere = tempfile::tempdir().expect("tempdir");
	let real = elsewhere.path().join("day.jsonl");
	std::fs::write(
		&real,
		[line(1, &zero(), at(DAY, 1), accepted(1)), b"\n".to_vec()].concat(),
	)
	.expect("write");
	std::fs::create_dir_all(dir.path().join(CHAIN_DIR)).expect("dir");
	std::os::unix::fs::symlink(&real, day_path(dir.path())).expect("link");
	assert!(
		first_break(dir.path()).starts_with("2026-10-14: cannot read the day file ("),
		"a link is not followed"
	);
}

#[test]
fn the_writer_keeps_time_monotonic_when_the_clock_goes_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	chain.append_at(at(DAY, 5), accepted(1)).expect("append");
	chain
		.append_at(at(DAY, 4), delivered(1))
		.expect("append with the clock behind");
	let walk =
		walk_day(dir.path(), Day(DAY), Some(Position::START), |_, _, _| {}).expect("verifies");
	assert_eq!(
		(walk.records, walk.last.seq, walk.last.time),
		(2, 2, at(DAY, 5))
	);
}

#[test]
fn the_writer_refuses_to_append_onto_a_tail_it_cannot_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	let mut bytes = std::fs::read(day_path(dir.path())).expect("read");
	bytes.extend_from_slice(b"{\"v\":1}\n");
	std::fs::write(day_path(dir.path()), bytes).expect("write");
	let error = chain
		.append_at(at(DAY, 2), delivered(1))
		.expect_err("refused");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
