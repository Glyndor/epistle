use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Entry, FORMAT_VERSION, Record};
use crate::evidence::test_support::{accepted, at, delivered};

const DAY: i64 = 20_740;

/// A day of four records; returns the evidence root, the lines and their hashes.
fn four_records() -> (tempfile::TempDir, Vec<Vec<u8>>, Vec<[u8; 32]>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	let mut hashes = Vec::new();
	for (hour, entry) in [accepted(1), delivered(1), accepted(2), delivered(2)]
		.into_iter()
		.enumerate()
	{
		hashes.push(chain.append(at(DAY, hour as u64), entry).expect("append"));
	}
	let lines = read_lines(dir.path());
	(dir, lines, hashes)
}

fn path(root: &Path) -> std::path::PathBuf {
	day_file(&root.join(CHAIN_DIR), Day(DAY))
}

fn read_lines(root: &Path) -> Vec<Vec<u8>> {
	std::fs::read(path(root))
		.expect("read")
		.split(|byte| *byte == b'\n')
		.filter(|line| !line.is_empty())
		.map(<[u8]>::to_vec)
		.collect()
}

fn write_lines(root: &Path, lines: &[Vec<u8>]) {
	let mut bytes = Vec::new();
	for line in lines {
		bytes.extend_from_slice(line);
		bytes.push(b'\n');
	}
	std::fs::write(path(root), bytes).expect("write");
}

fn first_break(root: &Path) -> String {
	walk_day(root, Day(DAY), Some(GENESIS), |_, _, _| {})
		.expect_err("the day must not verify")
		.to_string()
}

fn unchained(line: u64, found: &[u8; 32], expected: &[u8; 32]) -> String {
	format!(
		"2026-10-14 line {line}: record does not chain onto the one before it (prev {}, expected {}): \
		 a record was edited, deleted, reordered or inserted",
		to_hex(found),
		to_hex(expected)
	)
}

#[test]
fn an_untouched_day_verifies() {
	let (dir, _, hashes) = four_records();
	let mut seen = Vec::new();
	let walk = walk_day(dir.path(), Day(DAY), Some(GENESIS), |line, _, hash| {
		seen.push((line, *hash))
	})
	.expect("verifies");
	assert_eq!(walk.records, 4);
	assert_eq!(walk.first_prev, GENESIS);
	assert_eq!(walk.last, hashes[3]);
	assert_eq!(
		seen.iter().map(|(_, hash)| *hash).collect::<Vec<_>>(),
		hashes
	);
}

#[test]
fn an_edited_record_is_found_at_the_line_after_it() {
	let (dir, mut lines, hashes) = four_records();
	let text = String::from_utf8(lines[1].clone()).expect("utf8");
	lines[1] = text.replace("250 2.0.0 OK", "550 5.1.1 no").into_bytes();
	write_lines(dir.path(), &lines);
	let edited = sha256(&lines[1]);
	assert_eq!(first_break(dir.path()), unchained(3, &hashes[1], &edited));
}

#[test]
fn a_deleted_record_is_found() {
	let (dir, mut lines, hashes) = four_records();
	lines.remove(1);
	write_lines(dir.path(), &lines);
	assert_eq!(
		first_break(dir.path()),
		unchained(2, &hashes[1], &hashes[0])
	);
}

#[test]
fn reordered_records_are_found() {
	let (dir, mut lines, hashes) = four_records();
	lines.swap(1, 2);
	write_lines(dir.path(), &lines);
	assert_eq!(
		first_break(dir.path()),
		unchained(2, &hashes[1], &hashes[0])
	);
}

#[test]
fn an_inserted_record_is_found_even_when_it_chains_onto_its_predecessor() {
	let (dir, mut lines, hashes) = four_records();
	let forged = Record {
		v: FORMAT_VERSION,
		prev: to_hex(&hashes[0]),
		time: at(DAY, 0),
		entry: accepted(99),
	}
	.to_line()
	.expect("line");
	let forged_hash = sha256(&forged);
	lines.insert(1, forged);
	write_lines(dir.path(), &lines);
	assert_eq!(
		first_break(dir.path()),
		unchained(3, &hashes[0], &forged_hash)
	);
}

#[test]
fn a_torn_or_foreign_line_is_reported() {
	let (dir, lines, _) = four_records();
	let mut bytes = std::fs::read(path(dir.path())).expect("read");
	bytes.extend_from_slice(b"{\"v\":1");
	std::fs::write(path(dir.path()), &bytes).expect("write");
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 5: incomplete last record (interrupted write)"
	);
	let mut foreign = lines.clone();
	foreign[2] = b"not json".to_vec();
	write_lines(dir.path(), &foreign);
	assert!(
		first_break(dir.path()).starts_with("2026-10-14 line 3: not an evidence record ("),
		"a foreign line is named"
	);
}

#[test]
fn a_future_format_is_not_read_as_this_one() {
	let (dir, mut lines, _) = four_records();
	let text = String::from_utf8(lines[0].clone()).expect("utf8");
	lines[0] = text.replacen("{\"v\":1,", "{\"v\":2,", 1).into_bytes();
	write_lines(dir.path(), &lines);
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 1: not an evidence record (format version 2)"
	);
}

#[test]
fn a_huge_line_is_skipped_without_being_read_whole() {
	let (dir, _, _) = four_records();
	let mut bytes = vec![b'x'; 8 * crate::evidence::record::MAX_LINE];
	bytes.push(b'\n');
	std::fs::write(path(dir.path()), &bytes).expect("write");
	assert_eq!(
		first_break(dir.path()),
		"2026-10-14 line 1: line longer than any evidence record"
	);
}

#[test]
fn record_kinds_round_trip_through_the_line_format() {
	let (dir, _, _) = four_records();
	let mut kinds = Vec::new();
	walk_day(dir.path(), Day(DAY), None, |_, record, _| {
		kinds.push(match &record.entry {
			Entry::Accepted(_) => "accepted",
			Entry::Outcome(_) => "outcome",
			_ => "other",
		})
	})
	.expect("verifies");
	assert_eq!(kinds, ["accepted", "outcome", "accepted", "outcome"]);
}
