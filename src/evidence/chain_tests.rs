use super::*;
use crate::evidence::record::{GENESIS, Record, hash_from_hex, sha256};
use crate::evidence::test_support::{accepted, at, delivered};

const DAY: i64 = 20_740;

fn lines_of(chain: &Chain, day: Day) -> Vec<Vec<u8>> {
	let bytes = fs::read(chain.day_file(day)).expect("read day file");
	bytes
		.split(|byte| *byte == b'\n')
		.filter(|line| !line.is_empty())
		.map(<[u8]>::to_vec)
		.collect()
}

fn prev_of(line: &[u8]) -> [u8; 32] {
	let record: Record = serde_json::from_slice(line).expect("record");
	hash_from_hex(&record.prev).expect("hex prev")
}

#[test]
fn each_record_names_the_hash_of_the_line_before_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	let first = chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	let second = chain.append_at(at(DAY, 2), delivered(1)).expect("append");
	let lines = lines_of(&chain, Day(DAY));
	assert_eq!(lines.len(), 2);
	assert_eq!(prev_of(&lines[0]), GENESIS);
	assert_eq!(sha256(&lines[0]), first);
	assert_eq!(prev_of(&lines[1]), first);
	assert_eq!(sha256(&lines[1]), second);
}

#[test]
fn the_chain_continues_across_days_and_reopens() {
	let dir = tempfile::tempdir().expect("tempdir");
	let last_of_day = {
		let chain = Chain::open(dir.path()).expect("open");
		chain.append_at(at(DAY, 23), accepted(1)).expect("append")
	};
	let chain = Chain::open(dir.path()).expect("reopen");
	chain
		.append_at(at(DAY + 2, 1), accepted(2))
		.expect("append next day");
	let lines = lines_of(&chain, Day(DAY + 2));
	assert_eq!(prev_of(&lines[0]), last_of_day);
	assert_eq!(chain.days().expect("days"), vec![Day(DAY), Day(DAY + 2)]);
}

#[test]
fn files_and_directory_are_owner_only() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	let file = fs::metadata(chain.day_file(Day(DAY))).expect("stat file");
	assert_eq!(file.permissions().mode() & 0o777, 0o600);
	let directory = fs::metadata(chain.dir()).expect("stat dir");
	assert_eq!(directory.permissions().mode() & 0o777, 0o700);
}

#[test]
fn an_interrupted_last_line_is_cut_off_before_the_next_append() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	let kept = chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	let path = chain.day_file(Day(DAY));
	let mut file = OpenOptions::new().append(true).open(&path).expect("open");
	file.write_all(b"{\"v\":1,\"prev\":\"00")
		.expect("torn write");
	drop(file);
	chain
		.append_at(at(DAY, 2), accepted(2))
		.expect("append after torn");
	let lines = lines_of(&chain, Day(DAY));
	assert_eq!(lines.len(), 2, "the torn bytes are gone");
	assert_eq!(prev_of(&lines[1]), kept);
}

#[test]
fn a_torn_first_line_leaves_the_day_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	fs::write(chain.day_file(Day(DAY)), b"{\"v\":1").expect("torn");
	chain.append_at(at(DAY, 2), accepted(2)).expect("append");
	let lines = lines_of(&chain, Day(DAY));
	assert_eq!(lines.len(), 1);
	assert_eq!(prev_of(&lines[0]), GENESIS);
}

#[test]
fn the_last_hash_is_found_without_reading_the_day() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	let mut last = GENESIS;
	for n in 0..300 {
		last = chain.append_at(at(DAY, 1), accepted(n)).expect("append");
	}
	let path = chain.day_file(Day(DAY));
	assert_eq!(last_line_hash(&path, false).expect("tail"), Some(last));
	let long_tail = vec![b'x'; 3 * MAX_LINE];
	let mut file = OpenOptions::new().append(true).open(&path).expect("open");
	file.write_all(&long_tail).expect("garbage");
	drop(file);
	let error = last_line_hash(&path, false).expect_err("garbage tail");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn an_oversized_record_is_refused_and_nothing_is_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	let mut entry = accepted(1);
	if let Entry::Accepted(accepted) = &mut entry {
		accepted.recipients = vec!["r@example.net".repeat(64); 400];
	}
	let error = chain.append_at(at(DAY, 1), entry).expect_err("too long");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert!(!chain.day_file(Day(DAY)).exists());
}

#[test]
fn two_writers_never_fork_the_chain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let threads: Vec<_> = (0..4)
		.map(|writer| {
			let root = root.clone();
			std::thread::spawn(move || {
				let chain = Chain::open(&root).expect("open");
				for n in 0..50 {
					chain
						.append_at(at(DAY, 1), accepted(writer * 100 + n))
						.expect("append");
				}
			})
		})
		.collect();
	for thread in threads {
		thread.join().expect("writer");
	}
	let chain = Chain::open(&root).expect("open");
	let lines = lines_of(&chain, Day(DAY));
	assert_eq!(lines.len(), 200);
	let mut expected = GENESIS;
	for (index, line) in lines.iter().enumerate() {
		assert_eq!(prev_of(line), expected, "line {} forks", index + 1);
		expected = sha256(line);
	}
}
