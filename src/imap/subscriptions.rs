//! IMAP subscription list (`<account>/.subscriptions`): one mailbox name
//! per line, INBOX always implicitly subscribed.
//!
//! Subscriptions are advisory: an unsubscribed mailbox still appears in
//! `LIST`, the flag only stops the client from auto-opening it. epistle
//! writes the file when the client calls SUBSCRIBE/UNSUBSCRIBE. A
//! subscription outlives its mailbox: LIST-EXTENDED reports a subscribed
//! name that no longer exists as `\NonExistent` (RFC 5258).

use std::path::{Path, PathBuf};

use crate::util::path_component::AccountName;
use crate::util::path_containment::contained;

/// The `.subscriptions` file of `account`, resolved and checked to lie inside
/// the account's own directory.
fn subscriptions_file(data_dir: &Path, account: &str) -> std::io::Result<PathBuf> {
	let root = AccountName::new(account)?.root(data_dir)?;
	contained(&root, &root.join(".subscriptions"))
}

/// The one spelling a subscription is kept under: `INBOX` and a first level
/// equal to it in any case are upper case, every other name is case
/// sensitive (RFC 9051 §5.1).
fn canonical(mailbox: &str) -> String {
	if mailbox.eq_ignore_ascii_case("INBOX") {
		"INBOX".to_string()
	} else {
		crate::util::mailbox_path::canonical(mailbox).into_owned()
	}
}

/// Subscribe to a mailbox (the mailbox must already exist).
pub fn subscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	if !super::mailbox::exists(data_dir, account, mailbox) {
		return Err(std::io::Error::other("no such mailbox"));
	}
	let normalized = canonical(mailbox);
	let mut subs = list_subscribed(data_dir, account);
	if !subs.contains(&normalized) {
		subs.push(normalized);
		write_subscriptions(data_dir, account, &subs)?;
	}
	Ok(())
}

/// Remove a subscription. Silently succeeds if not subscribed.
pub fn unsubscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let normalized = canonical(mailbox);
	let subs: Vec<String> = list_subscribed(data_dir, account)
		.into_iter()
		.filter(|s| *s != normalized)
		.collect();
	write_subscriptions(data_dir, account, &subs)
}

/// Subscribed mailboxes; INBOX is always subscribed.
pub fn list_subscribed(data_dir: &Path, account: &str) -> Vec<String> {
	let mut names: Vec<String> = subscriptions_file(data_dir, account)
		.and_then(std::fs::read_to_string)
		.unwrap_or_default()
		.lines()
		.filter(|l| !l.is_empty())
		.map(canonical)
		.collect();
	if !names.iter().any(|n| n == "INBOX") {
		names.insert(0, "INBOX".to_string());
	}
	names
}

fn write_subscriptions(data_dir: &Path, account: &str, names: &[String]) -> std::io::Result<()> {
	let path = subscriptions_file(data_dir, account)?;
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	std::fs::write(
		&path,
		names.iter().fold(String::new(), |mut s, n| {
			s.push_str(n);
			s.push('\n');
			s
		}),
	)
}
