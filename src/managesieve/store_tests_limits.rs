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
	// 100 characters of two octets: exactly 200 octets, at the octet limit.
	s.put(&"\u{e9}".repeat(100), "keep;\r\n")
		.expect("200 octets");
	// 101 of them is 202 octets, over the limit though under 128 characters.
	assert_eq!(
		s.put(&"\u{e9}".repeat(101), "keep;\r\n"),
		Err(StoreError::InvalidName)
	);
}
