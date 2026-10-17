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

#[test]
fn bytes_moved_across_the_end_of_the_day_make_another_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path();
	let chain = crate::evidence::chain::Chain::open(root).expect("chain");
	let path = chain.day_file(Day(DAY));
	let checkpoint = files(root, Day(DAY));
	std::fs::create_dir_all(checkpoint.json.parent().expect("dir")).expect("mkdir");
	let state = |day: &[u8], json: Option<&[u8]>| {
		std::fs::write(&path, day).expect("day");
		match json {
			Some(json) => std::fs::write(&checkpoint.json, json).expect("json"),
			None => {
				let _ = std::fs::remove_file(&checkpoint.json);
			}
		}
		day_state(root, Day(DAY), None).expect("state")
	};
	// What the day ends with, moved to what comes after it, and the trailer
	// an older encoding put after the day's bytes inside the day.
	let trailer = [b"lines".as_slice(), &12u64.to_be_bytes()].concat();
	let pairs = [
		(
			state(b"abc\n", Some(b"def")),
			state(b"abc\nd\n", Some(b"ef")),
		),
		(
			state(b"abc\n", Some(b"json")),
			state(&[b"abc\n".as_slice(), &trailer].concat(), None),
		),
		(
			state(&[b"abc\n".as_slice(), &trailer].concat(), Some(b"x")),
			state(b"abc\n", Some(&[trailer.as_slice(), b"x"].concat())),
		),
	];
	for (index, (one, other)) in pairs.iter().enumerate() {
		assert_ne!(one, other, "pair {index} shares a digest");
	}
}

#[test]
fn bytes_moved_between_the_checkpoint_files_make_another_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path();
	let paths = files(root, Day(DAY));
	std::fs::create_dir_all(paths.json.parent().expect("dir")).expect("mkdir");
	let state = |json: Option<&[u8]>, sig: Option<&[u8]>, tsr: Option<&[u8]>| {
		for (path, bytes) in [(&paths.json, json), (&paths.sig, sig), (&paths.tsr, tsr)] {
			match bytes {
				Some(bytes) => std::fs::write(path, bytes).expect("write"),
				None => {
					let _ = std::fs::remove_file(path);
				}
			}
		}
		day_state(root, Day(DAY), None).expect("state")
	};
	let mut seen = std::collections::BTreeSet::new();
	// The same bytes, cut at other places between the files, or left out of
	// one of them: every arrangement is a state of its own.
	type Bytes<'a> = Option<&'a [u8]>;
	let arrangements: [(Bytes, Bytes, Bytes); 13] = [
		(Some(b"abc"), Some(b"def"), None),
		(Some(b"ab"), Some(b"cdef"), None),
		(Some(b"abcd"), Some(b"ef"), None),
		(Some(b"abc"), None, Some(b"def")),
		(None, Some(b"abc"), Some(b"def")),
		(Some(b"abcdef"), None, None),
		(None, Some(b"abcdef"), None),
		(None, None, Some(b"abcdef")),
		(Some(b""), None, None),
		(None, None, None),
		(Some(b"abc"), Some(b"def"), Some(b"")),
		// One file carrying the name and the start of the next, so that
		// without lengths the two would hash the same bytes in the same order.
		(Some(b"j"), Some(b"a\x03tsrb"), Some(b"c")),
		(Some(b"j"), Some(b"a"), Some(b"b\x03tsrc")),
	];
	for arrangement in arrangements {
		let digest = state(arrangement.0, arrangement.1, arrangement.2);
		assert!(
			seen.insert(digest),
			"two different arrangements of the checkpoint files have the same state: {arrangement:?}"
		);
	}
}
