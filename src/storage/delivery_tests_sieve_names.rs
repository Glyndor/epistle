//! Sieve names folders in UTF-8 (RFC 5228) while IMAP stores them
//! under their modified UTF-7 spelling, so `fileinto` must land in the
//! folder an IMAP client created under the same name, never in a second
//! folder spelled differently, and never lose the message.

use std::path::Path;

use super::tests::{directory, message};
use super::*;

fn write_filter(root: &Path, script: &str) {
	let dir = root.join("accounts").join("alice");
	fs::create_dir_all(&dir).expect("mkdir");
	fs::write(dir.join("filter.sieve"), script).expect("write filter");
}

fn count(dir: &Path) -> usize {
	fs::read_dir(dir)
		.map(|entries| entries.count())
		.unwrap_or(0)
}

fn folder_messages(root: &Path, stored: &str) -> usize {
	count(&root.join("accounts/alice/folders").join(stored).join("new"))
}

fn inbox_messages(root: &Path) -> usize {
	count(&root.join("accounts/alice/new"))
}

/// Every folder of the account, by its on-disk name.
fn folders(root: &Path) -> Vec<String> {
	let mut names: Vec<String> = fs::read_dir(root.join("accounts/alice/folders"))
		.map(|entries| {
			entries
				.map(|entry| {
					entry
						.expect("entry")
						.file_name()
						.to_string_lossy()
						.into_owned()
				})
				.collect()
		})
		.unwrap_or_default();
	names.sort();
	names
}

fn deliver_with(root: &Path, script: &str) {
	let delivery = LocalDelivery::new(root, directory()).expect("delivery");
	write_filter(root, script);
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("deliver");
}

#[test]
fn fileinto_a_utf8_name_lands_in_the_folder_imap_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::imap::mailbox::ensure_defaults(dir.path(), "alice").expect("defaults");
	let stored = crate::util::mutf7::encode("Año");
	assert_eq!(stored, "A&APE-o");
	crate::imap::mailbox::create(dir.path(), "alice", &stored).expect("IMAP CREATE");
	let before = folders(dir.path());
	deliver_with(dir.path(), "fileinto \"Año\";");
	assert_eq!(
		folder_messages(dir.path(), "A&APE-o"),
		1,
		"filed into A&APE-o"
	);
	assert_eq!(inbox_messages(dir.path()), 0, "nothing kept in INBOX");
	assert_eq!(folders(dir.path()), before, "no second folder");
}

#[test]
fn fileinto_create_makes_the_folder_under_its_imap_spelling() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver_with(
		dir.path(),
		"require [\"fileinto\", \"mailbox\"]; fileinto :create \"Proyectos Año\";",
	);
	assert_eq!(
		folder_messages(dir.path(), "Proyectos A&APE-o"),
		1,
		"filed into Proyectos A&APE-o"
	);
	assert!(
		!folders(dir.path()).contains(&"Proyectos Año".to_string()),
		"{:?}",
		folders(dir.path())
	);
	assert_eq!(
		crate::imap::mailbox::list(dir.path(), "alice")
			.iter()
			.filter(|name| name.starts_with("Proyectos"))
			.collect::<Vec<_>>(),
		["Proyectos A&APE-o"],
		"IMAP lists the folder the filter created"
	);
}

#[test]
fn fileinto_a_name_imap_cannot_create_keeps_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver_with(dir.path(), "fileinto \"Proyectos/Año\";");
	assert_eq!(
		inbox_messages(dir.path()),
		1,
		"a failed fileinto falls back to the implicit keep (RFC 5228 §2.10.6)"
	);
	assert!(
		folders(dir.path())
			.iter()
			.all(|name| !name.contains("Proyectos")),
		"{:?}",
		folders(dir.path())
	);
}

#[test]
fn mailboxexists_keeps_the_message_when_the_folder_does_not_exist() {
	// The interpreter sees the account's mailbox list (so mailboxexists
	// is true only for real folders) and a missing folder short-circuits
	// the body, leaving the implicit keep.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver_with(
		dir.path(),
		"require \"mailbox\"; \
		 if mailboxexists \"Junk\" { fileinto \"Junk\"; }",
	);
	assert_eq!(
		inbox_messages(dir.path()),
		1,
		"mailboxexists false on a missing folder: the implicit keep stands"
	);
	assert_eq!(
		folder_messages(dir.path(), "Junk"),
		0,
		"the fileinto never ran; no folder was created"
	);
}

#[test]
fn mailboxexists_uses_an_existing_folder() {
	// IMAP CREATEd folders appear in the mailbox list, so the fileinto
	// branch runs and the message lands there.
	let dir = tempfile::tempdir().expect("tempdir");
	crate::imap::mailbox::create(dir.path(), "alice", "Junk").expect("IMAP CREATE");
	deliver_with(
		dir.path(),
		"require \"mailbox\"; \
		 if mailboxexists \"Junk\" { fileinto \"Junk\"; }",
	);
	assert_eq!(folder_messages(dir.path(), "Junk"), 1);
	assert_eq!(inbox_messages(dir.path()), 0);
}
