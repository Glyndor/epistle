use std::sync::Arc;

use super::base::{directory, message};
use super::*;
use crate::imap::mailbox::Snapshot;
use crate::imap::special_use::{FolderPolicy, Role, roles};

fn count(data: &std::path::Path, folder: &str) -> usize {
	Snapshot::open(data, "alice", folder, &MessageCrypto::disabled())
		.map_or(0, |snapshot| snapshot.len())
}

fn single_spam() -> Arc<FolderPolicy> {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[storage.folders]\nsingle_spam_folder = true\n",
		dir.path()
	);
	let config = crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
		.expect("config");
	Arc::new(FolderPolicy::from_config(&config))
}

#[test]
fn by_default_each_filter_keeps_its_own_folder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	for target in ["Rejects", "Junk"] {
		sink.deliver_routed(&message(&["alice@example.org"]), Some(target))
			.expect("deliver");
	}
	assert_eq!(count(dir.path(), "Rejects"), 1);
	assert_eq!(count(dir.path(), "Junk"), 1);
}

#[test]
fn with_one_spam_folder_every_filter_lands_in_it_and_rejects_is_not_made() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = LocalDelivery::new(dir.path(), directory())
		.expect("delivery")
		.with_folders(single_spam());
	for target in ["Rejects", "Junk", "rejects"] {
		sink.deliver_routed(&message(&["alice@example.org"]), Some(target))
			.expect("deliver");
	}
	assert_eq!(count(dir.path(), "Junk"), 3);
	assert!(!crate::imap::mailbox::exists(
		dir.path(),
		"alice",
		"Rejects"
	));
}

#[test]
fn a_spam_folder_the_account_chose_receives_the_filters() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	sink.deliver_routed(&message(&["alice@example.org"]), None)
		.expect("first delivery makes the folders");
	crate::imap::mailbox::create(dir.path(), "alice", "Basura").expect("create");
	roles::set(dir.path(), "alice", Role::Junk, "Basura").expect("role");
	sink.deliver_routed(&message(&["alice@example.org"]), Some("Rejects"))
		.expect("deliver");
	assert_eq!(count(dir.path(), "Basura"), 1);
	assert_eq!(count(dir.path(), "Rejects"), 0);
}
