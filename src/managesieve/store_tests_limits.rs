//! The limits every protocol shares: script size, script count, name rules.

use super::*;

fn store(dir: &std::path::Path) -> ScriptStore {
	ScriptStore::new(dir, "alice")
}

/// A valid script of exactly `size` octets: `keep;` and a comment as padding,
/// so the only thing that can refuse it is its size.
fn script_of(size: usize) -> String {
	let head = "keep;\r\n#";
	let tail = "\r\n";
	let pad = size - head.len() - tail.len();
	format!("{head}{}{tail}", "x".repeat(pad))
}

#[test]
fn a_script_over_the_size_limit_is_refused_and_not_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let result = s.put("big", &script_of(MAX_SCRIPT_BYTES + 1));
	assert_eq!(result, Err(StoreError::TooLarge));
	assert_eq!(s.get("big"), Err(StoreError::NoSuchScript));
}

#[test]
fn a_script_of_exactly_the_size_limit_is_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("edge", &script_of(MAX_SCRIPT_BYTES))
		.expect("a script at the limit is accepted");
	assert_eq!(s.get("edge").expect("get").len(), MAX_SCRIPT_BYTES);
}

#[test]
fn checking_a_script_applies_the_same_size_limit() {
	let result = ScriptStore::validate(&script_of(MAX_SCRIPT_BYTES + 1));
	assert_eq!(result, Err(StoreError::TooLarge));
	assert_eq!(ScriptStore::validate(&script_of(MAX_SCRIPT_BYTES)), Ok(()));
}

#[test]
fn the_script_count_limit_refuses_a_new_name_but_not_a_rewrite() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	for index in 0..MAX_SCRIPTS {
		s.put(&format!("s{index}"), "keep;\r\n").expect("put");
	}
	assert_eq!(
		s.put("one-more", "keep;\r\n"),
		Err(StoreError::TooManyScripts)
	);
	assert_eq!(s.get("one-more"), Err(StoreError::NoSuchScript));
	assert_eq!(s.list().expect("list").len(), MAX_SCRIPTS);
	s.put("s0", "discard;\r\n")
		.expect("rewriting an existing script is not a new script");
	assert_eq!(s.get("s0").expect("get"), "discard;\r\n");
}

#[test]
fn have_space_applies_the_size_and_count_limits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	assert_eq!(s.have_space("a", MAX_SCRIPT_BYTES as u64), Ok(()));
	assert_eq!(
		s.have_space("a", MAX_SCRIPT_BYTES as u64 + 1),
		Err(StoreError::TooLarge)
	);
	assert_eq!(s.have_space("a/b", 1), Err(StoreError::InvalidName));
	for index in 0..MAX_SCRIPTS {
		s.put(&format!("s{index}"), "keep;\r\n").expect("put");
	}
	assert_eq!(s.have_space("new", 1), Err(StoreError::TooManyScripts));
	assert_eq!(s.have_space("s3", 1), Ok(()));
}

#[test]
fn names_with_controls_or_line_separators_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	for name in [
		"a\u{0}b",
		"a\tb",
		"a\u{1f}b",
		"a\u{7f}b",
		"a\u{85}b",
		"a\u{9f}b",
		"a\u{2028}b",
		"a\u{2029}b",
		"a/b",
		"a\\b",
		"\u{1b}[31mred",
	] {
		assert_eq!(
			s.put(name, "keep;\r\n"),
			Err(StoreError::InvalidName),
			"{name:?}"
		);
	}
	assert!(s.list().expect("list").is_empty());
}

#[test]
fn names_are_bounded_in_characters_and_in_octets() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	// 128 characters of one octet: at the character limit.
	s.put(&"a".repeat(MAX_NAME_CHARS), "keep;\r\n")
		.expect("128 characters");
	assert_eq!(
		s.put(&"a".repeat(MAX_NAME_CHARS + 1), "keep;\r\n"),
		Err(StoreError::InvalidName)
	);
	// 128 characters of four octets: 512 octets, at the octet limit, and
	// longer than a file name, so it is kept under a hashed file name.
	let long = "\u{1f600}".repeat(MAX_NAME_CHARS);
	assert_eq!(long.len(), MAX_NAME_BYTES);
	s.put(&long, "keep;\r\n").expect("512 octets");
	assert_eq!(s.get(&long).expect("get"), "keep;\r\n");
	assert!(
		s.list().expect("list").iter().any(|info| info.name == long),
		"the long name is listed as itself"
	);
	// 128 Chinese characters of three octets, 384 octets: also kept.
	let cjk = "\u{4e2d}".repeat(MAX_NAME_CHARS);
	s.put(&cjk, "keep;\r\n").expect("384 octets");
	// 129 characters is over the character limit.
	assert_eq!(
		s.put(&"\u{4e2d}".repeat(MAX_NAME_CHARS + 1), "keep;\r\n"),
		Err(StoreError::InvalidName)
	);
	// A name starting like a hashed file name is refused.
	assert_eq!(
		s.put("~sha256-abc", "keep;\r\n"),
		Err(StoreError::InvalidName)
	);
}

#[test]
fn a_name_too_long_for_a_file_survives_a_lost_index_a_rename_and_a_delete() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let long = "\u{4e2d}".repeat(MAX_NAME_CHARS);
	s.put(&long, "keep;\r\n").expect("put");
	let sieve = dir.path().join("alice/sieve");
	let names = |ext: &str| {
		std::fs::read_dir(&sieve)
			.expect("dir")
			.flatten()
			.filter(|entry| entry.file_name().to_string_lossy().ends_with(ext))
			.count()
	};
	assert_eq!(names(".name"), 1);
	std::fs::remove_file(sieve.join(".index.json")).expect("drop the index");
	let listed = s.list().expect("list");
	assert_eq!(listed.len(), 1);
	assert_eq!(listed[0].name, long);
	s.rename(&long, "short").expect("rename");
	assert_eq!(names(".name"), 0, "the name file goes with the old name");
	assert_eq!(s.get("short").expect("get"), "keep;\r\n");
	s.rename("short", &long).expect("rename back");
	assert_eq!(names(".name"), 1);
	s.delete(&long).expect("delete");
	assert_eq!(names(".name"), 0);
	assert!(s.list().expect("list").is_empty());
}

/// Put a script file in the directory by hand, the way an operator might.
fn drop_in(dir: &std::path::Path, stem: &str) {
	let sieve = dir.join("alice/sieve");
	std::fs::create_dir_all(&sieve).expect("dir");
	std::fs::write(sieve.join(format!("{stem}.sieve")), "keep;\r\n").expect("write");
}

#[test]
fn a_file_put_in_by_hand_with_a_name_between_201_and_249_octets_is_not_listed() {
	// Such a name would be stored under a hashed file name, so the file
	// could be listed and never opened, and it would take one of the slots.
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	drop_in(dir.path(), &"\u{e9}".repeat(117));
	drop_in(dir.path(), &"\u{e9}".repeat(100));
	let names: Vec<String> = s
		.list()
		.expect("list")
		.into_iter()
		.map(|i| i.name)
		.collect();
	assert_eq!(names, vec!["\u{e9}".repeat(100)]);
	assert_eq!(s.get(&"\u{e9}".repeat(100)).expect("get"), "keep;\r\n");
}

#[test]
fn a_file_named_like_a_hashed_one_without_its_name_file_is_not_listed_or_opened() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	drop_in(dir.path(), "~sha256-legacy");
	assert!(s.list().expect("list").is_empty());
	assert_eq!(s.get("~sha256-legacy"), Err(StoreError::InvalidName));
	assert_eq!(s.delete("~sha256-legacy"), Err(StoreError::InvalidName));
}
