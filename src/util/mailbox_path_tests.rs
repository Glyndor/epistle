use super::*;

#[test]
fn hierarchical_names_are_folders() {
	for name in [
		"Work/Project",
		"a/b/c",
		"INBOX/child",
		"inbox/child",
		"Proyectos/A&APE-o",
		"Sent Items/2024",
		"a..b/c",
	] {
		assert!(valid_folder(name), "{name:?} is a valid folder");
	}
}

#[test]
fn every_level_follows_the_folder_rules() {
	for name in [
		"a//b",
		"/a",
		"a/",
		"/",
		"a/.hidden",
		"a/trail /b",
		"a/../b",
		"a/./b",
		"a/b\\c",
		"a/caf\u{e9}",
		"a/b:c",
		"INBOX",
		"inbox",
	] {
		assert!(!valid_folder(name), "{name:?} must be refused");
	}
}

#[test]
fn the_encoded_delimiter_is_never_a_valid_name() {
	// `&AC8-` decodes to `/`: a name holding it would map to the same
	// directory as the name with a real delimiter, so it is refused.
	for name in ["a&AC8-b", "&AC8-", "a/&AC8-", "x&AC8-y/z"] {
		assert!(!valid_folder(name), "{name:?} must be refused");
	}
	// As a directory name, `a&AC8-b` is `a/b` and nothing else.
	assert_eq!(stored_name("a&AC8-b").as_deref(), Some("a/b"));
}

#[test]
fn depth_is_bounded() {
	let at_limit = vec!["a"; MAX_DEPTH].join("/");
	assert!(valid_folder(&at_limit), "{MAX_DEPTH} levels are accepted");
	let over = vec!["a"; MAX_DEPTH + 1].join("/");
	assert!(!valid_folder(&over), "{} levels are refused", MAX_DEPTH + 1);
}

#[test]
fn the_on_disk_name_is_bounded() {
	// Two levels whose directory name is exactly the limit, then one byte more.
	let first = "a".repeat(128);
	let second = "b".repeat(MAX_DISK_NAME_LEN - 128 - 5);
	let at_limit = format!("{first}/{second}");
	assert_eq!(disk_name(&at_limit).len(), MAX_DISK_NAME_LEN);
	assert!(valid_folder(&at_limit));
	let over = format!("{at_limit}b");
	assert!(!valid_folder(&over));
	let long_level = format!("a/{}", "c".repeat(129));
	assert!(!valid_folder(&long_level), "one level over 128 bytes");
}

#[test]
fn disk_names_are_one_component_and_round_trip() {
	for name in [
		"Work",
		"Work/Project",
		"a/b/c",
		"INBOX/child",
		"Proyectos/A&APE-o",
		"x &- y",
	] {
		let disk = disk_name(name);
		assert!(!disk.contains('/'), "{disk:?} is one component");
		if valid_folder(name) {
			assert_eq!(stored_name(&disk).as_deref(), Some(name), "{name:?}");
		}
	}
	assert_eq!(disk_name("Work/Project"), "Work&AC8-Project");
	assert_eq!(disk_name("inbox/child"), "INBOX&AC8-child");
}

#[test]
fn only_the_canonical_directory_name_is_read_back() {
	// `inbox&AC8-x` would be the same mailbox as `INBOX&AC8-x`; only the
	// spelling disk_name makes is a mailbox.
	assert_eq!(stored_name("inbox&AC8-x"), None);
	assert_eq!(stored_name("INBOX&AC8-x").as_deref(), Some("INBOX/x"));
	assert_eq!(stored_name("a&AC8-&AC8-b"), None, "empty level");
	assert_eq!(stored_name("a&AC8-"), None, "trailing delimiter");
	assert_eq!(stored_name(".hidden"), None);
}

#[test]
fn hierarchy_helpers() {
	assert_eq!(parent("a/b/c"), Some("a/b"));
	assert_eq!(parent("a"), None);
	assert_eq!(leaf("a/b/c"), "c");
	assert_eq!(leaf("a"), "a");
	assert_eq!(ancestors("a/b/c").collect::<Vec<_>>(), ["a", "a/b"]);
	assert_eq!(ancestors("a").count(), 0);
	assert!(is_within("a/b", "a"));
	assert!(is_within("a", "a"));
	assert!(!is_within("ab", "a"));
	assert!(!is_within("a", "a/b"));
	assert_eq!(canonical("inbox/x"), "INBOX/x");
	assert_eq!(canonical("inboxes/x"), "inboxes/x");
	assert_eq!(canonical("Work/inbox"), "Work/inbox");
}
