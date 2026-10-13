//! The trace fields final delivery adds: `Return-Path` (RFC 5321 section
//! 4.4) on every copy that lands in a mailbox, first in the header block
//! and exactly once, whatever the message arrived with.

use std::path::Path;

use super::tests::{directory, message};
use super::*;
use crate::smtp::directory::AliasSpec;

/// Every stored message of `account`, whatever the mailbox.
pub(super) fn stored(root: &Path, account: &str) -> Vec<String> {
	let mut found = Vec::new();
	let mut pending = vec![root.join("accounts").join(account)];
	while let Some(path) = pending.pop() {
		let Ok(entries) = fs::read_dir(&path) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if path.is_dir() {
				pending.push(path);
			} else if path.extension().is_some_and(|ext| ext == "eml") {
				found.push(String::from_utf8(fs::read(&path).expect("read")).expect("utf8"));
			}
		}
	}
	found
}

/// How many header lines of `text` start the field `name`.
pub(super) fn fields(text: &str, name: &str) -> usize {
	let head = text.split("\r\n\r\n").next().unwrap_or_default();
	head.split("\r\n")
		.filter(|line| {
			line.split_once(':')
				.is_some_and(|(field, _)| field.eq_ignore_ascii_case(name))
		})
		.count()
}

const SPOOFED: &str = "Return-Path: <forged@attacker.example>\r\n\
	Subject: hi\r\nreturn-path:\r\n <second@attacker.example>\r\n\r\nReturn-Path: in the body stays\r\n";

#[test]
fn return_path_is_first_once_and_replaces_what_the_message_carried() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	let mut inbound = message(&["alice@example.org"]);
	inbound.data = SPOOFED.as_bytes().to_vec();
	delivery.deliver(inbound).expect("delivered");
	let copies = stored(dir.path(), "alice");
	assert_eq!(copies.len(), 1);
	let copy = &copies[0];
	assert!(
		copy.starts_with("Return-Path: <sender@elsewhere.example>\r\n"),
		"{copy}"
	);
	assert_eq!(fields(copy, "return-path"), 1, "{copy}");
	assert!(!copy.contains("attacker.example"), "{copy}");
	assert!(
		copy.ends_with("\r\n\r\nReturn-Path: in the body stays\r\n"),
		"{copy}"
	);
}

#[test]
fn the_null_sender_is_an_empty_return_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	let mut bounce = message(&["alice@example.org"]);
	bounce.reverse_path = String::new();
	delivery.deliver(bounce).expect("delivered");
	assert!(stored(dir.path(), "alice")[0].starts_with("Return-Path: <>\r\n"));
}

#[test]
fn every_alias_member_and_every_sieve_folder_copy_is_stamped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_aliases([(
			"team@example.org".to_string(),
			AliasSpec {
				members: vec!["alice@example.org".into(), "bob@example.org".into()],
				senders: Vec::new(),
				hidden: false,
				list_id: None,
			},
		)]),
	);
	let account = dir.path().join("accounts").join("bob");
	fs::create_dir_all(&account).expect("mkdir");
	fs::write(
		account.join("filter.sieve"),
		"require \"fileinto\"; fileinto \"Filed\"; keep;",
	)
	.expect("filter");
	let delivery = LocalDelivery::new(dir.path(), directory).expect("delivery");
	delivery
		.deliver(message(&["team@example.org"]))
		.expect("delivered");
	let alice = stored(dir.path(), "alice");
	let bob = stored(dir.path(), "bob");
	assert_eq!((alice.len(), bob.len()), (1, 2), "bob keeps and files");
	for copy in alice.iter().chain(&bob) {
		assert!(
			copy.starts_with("Return-Path: <sender@elsewhere.example>\r\n"),
			"{copy}"
		);
		assert_eq!(fields(copy, "return-path"), 1, "{copy}");
	}
}

#[test]
fn delivered_to_follows_the_return_path_and_names_the_address_delivered_to() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	let mut inbound = message(&["Also-Alice@Example.org"]);
	inbound.data = b"Delivered-To: someone@earlier.example\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
	delivery.deliver(inbound).expect("delivered");
	let copy = &stored(dir.path(), "alice")[0];
	assert!(
		copy.starts_with(
			"Return-Path: <sender@elsewhere.example>\r\nDelivered-To: also-alice@example.org\r\n\
			 Delivered-To: someone@earlier.example\r\n"
		),
		"ours first, the earlier hop's kept: {copy}"
	);
	assert_eq!(fields(copy, "delivered-to"), 2, "{copy}");
}

#[test]
fn an_alias_delivers_each_member_under_the_member_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_aliases([(
			"team@example.org".to_string(),
			AliasSpec {
				members: vec!["alice@example.org".into(), "Bob@example.org".into()],
				senders: Vec::new(),
				hidden: true,
				list_id: None,
			},
		)]),
	);
	let delivery = LocalDelivery::new(dir.path(), directory).expect("delivery");
	delivery
		.deliver(message(&["team@example.org"]))
		.expect("delivered");
	for (account, address) in [("alice", "alice@example.org"), ("bob", "bob@example.org")] {
		let copies = stored(dir.path(), account);
		assert_eq!(copies.len(), 1);
		let second = copies[0].split("\r\n").nth(1).unwrap_or_default();
		assert_eq!(second, format!("Delivered-To: {address}"), "{}", copies[0]);
		assert_eq!(fields(&copies[0], "delivered-to"), 1);
	}
}
