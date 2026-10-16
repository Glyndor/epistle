use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};

#[test]
fn any_line_or_checkpoint_file_changes_the_state() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let day = Day(DAY + 1);
	let before = day_state(root, day, None).expect("state");
	assert_eq!(day_state(root, day, None).expect("again"), before);
	let chain = crate::evidence::chain::Chain::open(root).expect("chain");
	let path = chain.day_file(day);
	let text = std::fs::read_to_string(&path).expect("read");
	std::fs::write(&path, text.replacen("Notice", "Notiće", 1)).expect("edit");
	assert_ne!(day_state(root, day, None).expect("edited"), before);
	std::fs::write(&path, &text).expect("restore");
	assert_eq!(day_state(root, day, None).expect("restored"), before);
	std::fs::remove_file(files(root, day).tsr).expect("rm token");
	assert_ne!(day_state(root, day, None).expect("no token"), before);
}

#[test]
fn only_the_lines_before_the_acknowledgement_count_in_its_own_day() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let day = Day(DAY);
	let whole = day_state(root, day, None).expect("whole");
	// The day has two lines; before line 3 is all of it.
	assert_eq!(day_state(root, day, Some(3)).expect("before 3"), whole);
	assert_ne!(day_state(root, day, Some(2)).expect("before 2"), whole);
}

#[test]
fn a_day_that_is_not_there_is_not_an_empty_one() {
	let fixture = Fixture::new();
	let missing = day_state(fixture.root(), Day(DAY + 90), None).expect("missing");
	assert_ne!(
		missing,
		day_state(fixture.root(), Day(DAY), Some(1)).expect("empty prefix")
	);
}

#[test]
fn a_line_without_an_end_is_hashed_as_it_comes_and_still_tells_files_apart() {
	use std::io::{Seek, SeekFrom, Write};
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path();
	let chain = crate::evidence::chain::Chain::open(root).expect("chain");
	let path = chain.day_file(Day(DAY));
	// Half a gibibyte of one line, as a sparse file: the digest must not hold
	// it, and a byte changed deep inside it must change the digest.
	let mut file = std::fs::File::create(&path).expect("create");
	file.set_len(512 * 1024 * 1024).expect("length");
	let first = day_state(root, Day(DAY), None).expect("state");
	file.seek(SeekFrom::Start(300 * 1024 * 1024)).expect("seek");
	file.write_all(b"x").expect("write");
	let second = day_state(root, Day(DAY), None).expect("state");
	assert_ne!(first, second);
	// The prefix before the first line end is all there is to hash here.
	assert_eq!(
		day_state(root, Day(DAY), Some(2)).expect("two"),
		second,
		"one line is the whole file"
	);
}
