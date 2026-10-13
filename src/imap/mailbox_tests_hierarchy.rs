//! Hierarchical mailboxes: CREATE makes missing superiors, DELETE refuses a
//! mailbox with children, RENAME moves the children along, and LIST reads the
//! flat directories back as hierarchical names.

use super::*;
use crate::imap::changelog::{self, Change, Op};
use crate::storage::MessageCrypto;

fn folders(dir: &Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(dir.join("accounts/alice/folders"))
		.map(|entries| {
			entries
				.flatten()
				.map(|entry| entry.file_name().to_string_lossy().into_owned())
				.collect()
		})
		.unwrap_or_default();
	names.sort();
	names
}

fn changes_since(dir: &Path, before: changelog::Position) -> Vec<Change> {
	let root = dir.join("accounts/alice");
	let (_, entries) = changelog::since(&root, before.epoch, before.current).expect("since");
	entries.into_iter().map(|entry| entry.change).collect()
}

fn position(dir: &Path) -> changelog::Position {
	let root = dir.join("accounts/alice");
	std::fs::create_dir_all(&root).expect("account");
	changelog::current(&root).expect("current")
}

#[test]
fn create_makes_the_missing_superiors_and_records_each() {
	let dir = tempfile::tempdir().expect("tempdir");
	let before = position(dir.path());
	create(dir.path(), "alice", "a/b/c").expect("create");
	assert_eq!(folders(dir.path()), ["a", "a&AC8-b", "a&AC8-b&AC8-c"]);
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "a", "a/b", "a/b/c"]);
	assert_eq!(
		changes_since(dir.path(), before),
		[
			Change::mailbox(Op::Created, "a"),
			Change::mailbox(Op::Created, "a/b"),
			Change::mailbox(Op::Created, "a/b/c"),
		]
	);
	// Each superior is a real, selectable mailbox.
	assert!(exists(dir.path(), "alice", "a/b"));
}

#[test]
fn create_with_a_trailing_delimiter_creates_the_name_without_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "Work/").expect("create");
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "Work"]);
	assert!(create(dir.path(), "alice", "Work/").is_err(), "exists");
	assert!(create(dir.path(), "alice", "/").is_err());
	assert!(create(dir.path(), "alice", "Work//").is_err());
}

#[test]
fn create_under_the_inbox_is_a_folder() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "inbox/child").expect("create");
	assert_eq!(folders(dir.path()), ["INBOX&AC8-child"]);
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "INBOX/child"]);
	assert!(exists(dir.path(), "alice", "INBOX/child"));
}

#[test]
fn delete_refuses_a_mailbox_with_children() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "a/b").expect("create");
	let error = delete(dir.path(), "alice", "a").expect_err("has children");
	assert!(error.to_string().starts_with("[HASCHILDREN]"), "{error}");
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "a", "a/b"]);
	delete(dir.path(), "alice", "a/b").expect("delete the leaf");
	delete(dir.path(), "alice", "a").expect("delete the parent");
	assert_eq!(list(dir.path(), "alice"), ["INBOX"]);
}

#[test]
fn delete_does_not_count_a_sibling_with_a_common_prefix_as_a_child() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "a").expect("create");
	create(dir.path(), "alice", "ab").expect("create");
	create(dir.path(), "alice", "a b/c").expect("create");
	delete(dir.path(), "alice", "a").expect("no child");
}

#[test]
fn rename_moves_every_child_with_its_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::disabled();
	create(dir.path(), "alice", "a/b/c").expect("create");
	let id = append(dir.path(), "alice", "a/b/c", &[], b"deep\r\n", &crypto).expect("append");
	create(dir.path(), "alice", "ab").expect("sibling");
	let before = position(dir.path());
	rename(dir.path(), "alice", "a", "x/y").expect("rename");
	assert_eq!(
		list(dir.path(), "alice"),
		["INBOX", "ab", "x", "x/y", "x/y/b", "x/y/b/c"]
	);
	let snapshot = Snapshot::open(dir.path(), "alice", "x/y/b/c", &crypto).expect("open");
	assert_eq!(
		snapshot.messages().map(|m| m.id()).collect::<Vec<_>>(),
		[id]
	);
	let changes = changes_since(dir.path(), before);
	for (op, name) in [
		(Op::Created, "x"),
		(Op::Destroyed, "a"),
		(Op::Created, "x/y"),
		(Op::Destroyed, "a/b/c"),
		(Op::Created, "x/y/b/c"),
	] {
		assert!(
			changes.contains(&Change::mailbox(op, name)),
			"{op:?} {name} in {changes:?}"
		);
	}
	assert!(changes.contains(&Change::email(Op::Updated, id)));
}

#[test]
fn rename_into_its_own_subtree_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "a/b").expect("create");
	for target in ["a/b/c", "a/x", "a"] {
		assert!(
			rename(dir.path(), "alice", "a", target).is_err(),
			"a -> {target}"
		);
	}
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "a", "a/b"]);
}

#[test]
fn rename_refuses_when_any_moved_name_is_taken() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "a/b").expect("create");
	create(dir.path(), "alice", "x/b").expect("create");
	delete(dir.path(), "alice", "x/b").expect("delete");
	create(dir.path(), "alice", "z/b").expect("create");
	// `a` -> `z` would move `a/b` onto the existing `z/b`.
	assert!(rename(dir.path(), "alice", "a", "z").is_err());
	assert_eq!(
		list(dir.path(), "alice"),
		["INBOX", "a", "a/b", "x", "z", "z/b"],
		"nothing moved"
	);
	// `a` -> `x` is free: `x` exists only as a leaf with no `x/b` now.
	assert!(rename(dir.path(), "alice", "a", "x").is_err(), "x exists");
	rename(dir.path(), "alice", "a", "q").expect("free target");
	assert_eq!(
		list(dir.path(), "alice"),
		["INBOX", "q", "q/b", "x", "z", "z/b"]
	);
}

#[test]
fn list_ignores_directories_that_are_not_a_canonical_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "Work").expect("create");
	let folders = dir.path().join("accounts/alice/folders");
	for stray in ["a&AC8-&AC8-b", "inbox&AC8-x", "Work&AC8-", ".hidden"] {
		std::fs::create_dir_all(folders.join(stray).join("new")).expect("stray");
	}
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "Work"]);
}

#[test]
fn many_mailboxes_and_a_name_at_the_depth_limit() {
	use crate::util::mailbox_path::MAX_DEPTH;
	let dir = tempfile::tempdir().expect("tempdir");
	for i in 0..300 {
		create(dir.path(), "alice", &format!("bulk/{i:03}")).expect("create");
	}
	let deepest = vec!["d"; MAX_DEPTH].join("/");
	create(dir.path(), "alice", &deepest).expect("create at the limit");
	let too_deep = format!("{deepest}/d");
	assert!(create(dir.path(), "alice", &too_deep).is_err());
	let names = list(dir.path(), "alice");
	assert_eq!(names.len(), 1 + 1 + 300 + MAX_DEPTH);
	assert!(names.contains(&deepest));
	assert!(!names.contains(&too_deep));
}

#[test]
fn rename_moves_nothing_when_a_child_target_is_taken() {
	// `q` is free but `q/b` exists (a store written before superiors were
	// made), so `a` -> `q` would move `a` and then fail on `a/b`.
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "a/b").expect("create");
	let folders = dir.path().join("accounts/alice/folders");
	std::fs::create_dir_all(folders.join("q&AC8-b/new")).expect("stray child");
	assert!(rename(dir.path(), "alice", "a", "q").is_err());
	assert_eq!(list(dir.path(), "alice"), ["INBOX", "a", "a/b", "q/b"]);
}
