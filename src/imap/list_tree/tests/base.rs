use super::*;

fn names(list: &[&str]) -> Vec<String> {
	list.iter().map(|name| name.to_string()).collect()
}

fn listed<'a>(entries: &[Entry<'a>]) -> Vec<&'a str> {
	entries.iter().map(|entry| entry.name).collect()
}

fn percent_of(prefix: &str) -> impl Fn(&str) -> bool + '_ {
	move |name| crate::imap::list_pattern::matches("", prefix, name)
}

#[test]
fn a_missing_level_stands_in_for_its_hidden_children() {
	let existing = names(&["INBOX", "a/b", "c"]);
	let entries = select(
		&existing,
		&[],
		|_, e| e,
		percent_of("%"),
		Hidden::Placeholder,
	);
	assert_eq!(listed(&entries), ["INBOX", "a", "c"]);
	let a = &entries[1];
	assert!(a.placeholder && !a.exists && a.has_children && !a.child_info);
	// `*` reaches `a/b` itself, so no placeholder is needed.
	let entries = select(
		&existing,
		&[],
		|_, e| e,
		percent_of("*"),
		Hidden::Placeholder,
	);
	assert_eq!(listed(&entries), ["INBOX", "a/b", "c"]);
}

#[test]
fn children_come_from_the_existing_names_only() {
	let existing = names(&["INBOX", "INBOX/x", "a", "ab", "a b/c"]);
	let entries = select(
		&existing,
		&[],
		|_, e| e,
		percent_of("*"),
		Hidden::Placeholder,
	);
	let with_children: Vec<&str> = entries
		.iter()
		.filter(|entry| entry.has_children)
		.map(|entry| entry.name)
		.collect();
	assert_eq!(with_children, ["INBOX"]);
	assert_eq!(listed(&entries)[0], "INBOX", "INBOX comes first");
}

#[test]
fn recursivematch_marks_only_a_parent_whose_qualifying_child_is_hidden() {
	let existing = names(&[
		"INBOX", "m", "m/t2", "m/t2/t1", "m/t8", "m/t8/t8", "m/t8/t9",
	]);
	let subscribed = names(&["m/t2/t1", "m/t8/t8", "m/t8/t9"]);
	let qualifies = |name: &str, _| subscribed.iter().any(|s| s == name);
	let entries = select(
		&existing,
		&subscribed,
		qualifies,
		percent_of("m/t2%"),
		Hidden::ChildInfo,
	);
	assert_eq!(listed(&entries), ["m/t2"]);
	assert!(entries[0].child_info && entries[0].exists);
	// `m*t8` reaches `m/t8/t8` but not `m/t8/t9`, which is still hidden.
	let entries = select(
		&existing,
		&subscribed,
		qualifies,
		percent_of("m*t8"),
		Hidden::ChildInfo,
	);
	assert_eq!(listed(&entries), ["m/t8", "m/t8/t8"]);
	assert!(entries[0].child_info && !entries[1].child_info);
	let entries = select(
		&existing,
		&subscribed,
		qualifies,
		percent_of("m/t2%"),
		Hidden::Skip,
	);
	assert!(entries.is_empty(), "{entries:?}");
}

#[test]
fn a_candidate_that_does_not_exist_is_reported_as_such() {
	let existing = names(&["INBOX"]);
	let subscribed = names(&["gone"]);
	let entries = select(
		&existing,
		&subscribed,
		|_, _| true,
		percent_of("*"),
		Hidden::Skip,
	);
	assert_eq!(listed(&entries), ["INBOX", "gone"]);
	assert!(!entries[1].exists && !entries[1].placeholder);
}

#[test]
fn many_names_and_deep_ones_list_in_one_pass() {
	use crate::util::mailbox_path::MAX_DEPTH;
	let mut existing = names(&["INBOX"]);
	for i in 0..20_000 {
		existing.push(format!("bulk{}/{i:05}", i % 100));
	}
	let deepest = vec!["d"; MAX_DEPTH].join("/");
	existing.push(deepest.clone());
	let entries = select(
		&existing,
		&[],
		|_, e| e,
		percent_of("%"),
		Hidden::Placeholder,
	);
	// INBOX, 100 placeholders `bulkN`, and the placeholder `d`.
	assert_eq!(entries.len(), 1 + 100 + 1);
	assert!(
		entries
			.iter()
			.all(|entry| entry.name == "INBOX" || entry.placeholder)
	);
	let entries = select(
		&existing,
		&[],
		|_, e| e,
		percent_of("*"),
		Hidden::Placeholder,
	);
	assert_eq!(entries.len(), existing.len());
}
