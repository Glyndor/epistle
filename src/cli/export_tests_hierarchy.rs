//! Maildir++ spells the hierarchy with `.` (`.Work.Project`), so subfolders
//! leave as one directory each and come back as subfolders.

use std::process::ExitCode;

use super::run_maildir;
use crate::imap::mailbox::{self, Snapshot};
use crate::storage::MessageCrypto;

fn count(data_dir: &std::path::Path, account: &str, name: &str) -> usize {
	Snapshot::open(data_dir, account, name, &MessageCrypto::disabled())
		.expect("open")
		.len()
}

#[test]
fn subfolders_export_as_maildir_plus_plus_and_import_back() {
	let crypto = MessageCrypto::disabled();
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::create(dir.path(), "alice", "Work/Project").expect("create");
	mailbox::append(
		dir.path(),
		"alice",
		"Work",
		&[],
		b"Subject: a\r\n\r\na\r\n",
		&crypto,
	)
	.expect("append");
	mailbox::append(
		dir.path(),
		"alice",
		"Work/Project",
		&[],
		b"Subject: b\r\n\r\nb\r\n",
		&crypto,
	)
	.expect("append");
	let out = tempfile::tempdir().expect("out");
	assert_eq!(
		run_maildir(dir.path(), "alice", &crypto, out.path()),
		ExitCode::SUCCESS
	);
	assert!(out.path().join(".Work.Project/cur").is_dir());
	assert!(!out.path().join(".Work/Project").exists(), "not nested");

	let dest = tempfile::tempdir().expect("dest");
	assert_eq!(
		crate::cli::import::run_maildir(dest.path(), "bob", &crypto, out.path()),
		ExitCode::SUCCESS
	);
	assert_eq!(
		mailbox::list(dest.path(), "bob"),
		["INBOX", "Work", "Work/Project"]
	);
	assert_eq!(count(dest.path(), "bob", "Work"), 1);
	assert_eq!(count(dest.path(), "bob", "Work/Project"), 1);
}

#[test]
fn a_dovecot_tree_imports_as_a_hierarchy_and_odd_dots_stay_flat() {
	let crypto = MessageCrypto::disabled();
	let src = tempfile::tempdir().expect("src");
	for folder in [".Lists.Rust", ".Projects..2024"] {
		let cur = src.path().join(folder).join("cur");
		std::fs::create_dir_all(&cur).expect("mkdir");
		std::fs::write(cur.join("m:2,S"), "Subject: x\n\nx\n").expect("write");
	}
	let dest = tempfile::tempdir().expect("dest");
	assert_eq!(
		crate::cli::import::run_maildir(dest.path(), "bob", &crypto, src.path()),
		ExitCode::SUCCESS
	);
	assert_eq!(
		mailbox::list(dest.path(), "bob"),
		["INBOX", "Lists", "Lists/Rust", "Projects..2024"]
	);
	assert_eq!(count(dest.path(), "bob", "Lists/Rust"), 1);
	assert_eq!(count(dest.path(), "bob", "Projects..2024"), 1);
}
