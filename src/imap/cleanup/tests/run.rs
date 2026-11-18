use std::path::Path;
use std::time::{Duration, SystemTime};

use super::*;
use crate::imap::internal_date::InternalDate;
use crate::imap::mailbox::{self, Snapshot};
use crate::storage::MessageCrypto;

const DAY: u64 = 86_400;
const MESSAGE: &[u8] = b"Subject: x\r\n\r\nbody\r\n";

fn now() -> u64 {
	SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

fn data(accounts: &[&str]) -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	for account in accounts {
		mailbox::ensure_defaults(dir.path(), account).expect("defaults");
	}
	dir
}

fn put(dir: &Path, account: &str, folder: &str, count: usize) {
	for _ in 0..count {
		mailbox::append(
			dir,
			account,
			folder,
			&[],
			MESSAGE,
			&MessageCrypto::disabled(),
		)
		.expect("append");
	}
}

fn held(dir: &Path, account: &str, folder: &str) -> usize {
	Snapshot::open(dir, account, folder, &MessageCrypto::disabled()).map_or(0, |s| s.len())
}

const TRASH_30: &str =
	"[storage.cleanup]\n[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 30\n";

fn apply(dir: &Path, policy: &Policy, now: u64) -> Report {
	run(dir, policy, 0, now, Mode::Apply).expect("run")
}

#[test]
fn removes_what_has_been_in_the_folder_longer_than_the_retention_and_nothing_else() {
	let dir = data(&["a@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 3);
	put(dir.path(), "a@example.org", "INBOX", 2);
	put(dir.path(), "a@example.org", "Sent", 2);
	let policy = policy(TRASH_30);
	// Ten days on: inside the window.
	let early = apply(dir.path(), &policy, now() + 10 * DAY);
	assert_eq!(early.messages(), 0);
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 3);
	// Thirty-one days on: due.
	let late = apply(dir.path(), &policy, now() + 31 * DAY);
	assert_eq!(late.messages(), 3);
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 0);
	assert_eq!(
		held(dir.path(), "a@example.org", "INBOX"),
		2,
		"INBOX is not a cleanup folder"
	);
	assert_eq!(
		held(dir.path(), "a@example.org", "Sent"),
		2,
		"no rule speaks for Sent"
	);
}

#[test]
fn a_message_with_an_old_internal_date_that_was_just_moved_in_stays() {
	let dir = data(&["a@example.org"]);
	let two_years_ago = SystemTime::now() - Duration::from_secs(730 * DAY);
	mailbox::append_dated(
		dir.path(),
		"a@example.org",
		"Trash",
		&[],
		Some(InternalDate {
			time: two_years_ago,
			zone: 0,
		}),
		MESSAGE,
		&MessageCrypto::disabled(),
	)
	.expect("append");
	let policy = policy(TRASH_30);
	assert_eq!(apply(dir.path(), &policy, now()).messages(), 0);
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 1);
	// Once it has been there for the retention, it goes.
	assert_eq!(apply(dir.path(), &policy, now() + 31 * DAY).messages(), 1);
}

#[test]
fn a_dry_run_counts_and_removes_nothing() {
	let dir = data(&["a@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 4);
	let policy = policy(TRASH_30);
	let later = now() + 31 * DAY;
	let report = run(dir.path(), &policy, 0, later, Mode::DryRun).expect("dry run");
	assert_eq!(report.messages(), 4);
	assert_eq!(report.folders.len(), 1);
	assert_eq!(report.folders[0].days, 30);
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 4);
	assert!(!dir.path().join("cleanup-cursor").exists());
}

#[test]
fn a_run_removes_at_most_the_cap_and_the_next_one_goes_on() {
	let dir = data(&["a@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 5);
	let policy = policy(
		"[storage.cleanup]\nmax_per_run = 2\n[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 30\n",
	);
	let later = now() + 31 * DAY;
	let first = apply(dir.path(), &policy, later);
	assert_eq!((first.messages(), first.capped), (2, true));
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 3);
	assert_eq!(apply(dir.path(), &policy, later).messages(), 2);
	let last = apply(dir.path(), &policy, later);
	assert_eq!((last.messages(), last.capped), (1, false));
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 0);
	assert!(
		!dir.path().join("cleanup-cursor").exists(),
		"a finished backlog leaves no cursor"
	);
}

#[test]
fn the_cursor_resumes_at_the_account_where_the_cap_ran_out() {
	let dir = data(&["a@example.org", "b@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 2);
	put(dir.path(), "b@example.org", "Trash", 2);
	let policy = policy(
		"[storage.cleanup]\nmax_per_run = 2\n[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 30\n",
	);
	let later = now() + 31 * DAY;
	let first = apply(dir.path(), &policy, later);
	assert_eq!(first.folders[0].account, "a@example.org");
	assert_eq!(held(dir.path(), "b@example.org", "Trash"), 2);
	let second = apply(dir.path(), &policy, later);
	assert_eq!(second.folders.len(), 1);
	assert_eq!(second.folders[0].account, "b@example.org");
	assert_eq!(held(dir.path(), "b@example.org", "Trash"), 0);
}

#[test]
fn a_preference_shortens_the_operators_retention_and_cannot_lengthen_it() {
	let dir = data(&["a@example.org", "b@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 1);
	put(dir.path(), "b@example.org", "Trash", 1);
	Prefs::set(dir.path(), "a@example.org", "trash", 5).expect("shorter");
	Prefs::set(dir.path(), "b@example.org", "trash", 90).expect("longer");
	let policy = policy(TRASH_30);
	// Ten days on: a's own five-day retention is due, b's ninety is not and
	// the operator's thirty is not either.
	let report = apply(dir.path(), &policy, now() + 10 * DAY);
	assert_eq!(report.messages(), 1);
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 0);
	assert_eq!(held(dir.path(), "b@example.org", "Trash"), 1);
	// Thirty-one days: the operator's cap holds b to thirty, not ninety.
	apply(dir.path(), &policy, now() + 31 * DAY);
	assert_eq!(held(dir.path(), "b@example.org", "Trash"), 0);
}

#[test]
fn a_zero_in_a_narrower_scope_keeps_everything_in_that_folder() {
	let dir = data(&["a@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 2);
	let policy = policy(
		"[storage.cleanup]\n[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 1\n[[storage.cleanup.rule]]\nscope = 'account'\nname = 'a@example.org'\nfolder = 'trash'\ndays = 0\n",
	);
	assert_eq!(apply(dir.path(), &policy, now() + 400 * DAY).messages(), 0);
	assert_eq!(held(dir.path(), "a@example.org", "Trash"), 2);
}

#[test]
fn a_removed_message_goes_to_the_archive_when_the_operator_keeps_deleted_mail() {
	let dir = data(&["a@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 2);
	let policy = policy(TRASH_30);
	let later = now() + 31 * DAY;
	let report = run(dir.path(), &policy, 7, later, Mode::Apply).expect("run");
	assert_eq!(report.messages(), 2);
	let root = crate::util::path_component::AccountName::new("a@example.org")
		.expect("name")
		.root(dir.path())
		.expect("root");
	let archived = crate::imap::archive::list(&root).expect("archive");
	assert_eq!(archived.len(), 2);
	assert!(archived.iter().all(|entry| entry.mailbox == "Trash"));
}

#[test]
fn a_removal_is_a_vanished_uid_for_the_sessions_that_have_the_folder_open() {
	let dir = data(&["a@example.org"]);
	put(dir.path(), "a@example.org", "Trash", 2);
	let before = Snapshot::open(
		dir.path(),
		"a@example.org",
		"Trash",
		&MessageCrypto::disabled(),
	)
	.expect("snapshot")
	.highest_modseq();
	apply(dir.path(), &policy(TRASH_30), now() + 31 * DAY);
	let after = Snapshot::open(
		dir.path(),
		"a@example.org",
		"Trash",
		&MessageCrypto::disabled(),
	)
	.expect("snapshot");
	assert_eq!(after.vanished_since(before).len(), 2);
}

#[test]
fn an_unreadable_account_directory_is_skipped_not_fatal() {
	let dir = data(&["a@example.org"]);
	std::fs::create_dir_all(dir.path().join("accounts/not an account/folders")).expect("dir");
	put(dir.path(), "a@example.org", "Trash", 1);
	let report = apply(dir.path(), &policy(TRASH_30), now() + 31 * DAY);
	assert_eq!(report.messages(), 1);
}
