//! IMAP subscription list (`<account>/.subscriptions`): one mailbox name
//! per line, INBOX always implicitly subscribed.
//!
//! Subscriptions are advisory: an unsubscribed mailbox still appears in
//! `LIST`, the flag only stops the client from auto-opening it. epistle
//! writes the file when the client calls SUBSCRIBE/UNSUBSCRIBE; otherwise
//! the list is just whatever the on-disk `folders/` directory happens to
//! contain (see [`super::mailbox::list`]).

use std::path::Path;

/// Subscribe to a mailbox (the mailbox must already exist).
pub fn subscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	if !super::mailbox::exists(data_dir, account, mailbox) {
		return Err(std::io::Error::other("no such mailbox"));
	}
	let normalized = if mailbox.eq_ignore_ascii_case("INBOX") {
		"INBOX".to_string()
	} else {
		mailbox.to_string()
	};
	let mut subs = list_subscribed(data_dir, account);
	if !subs.iter().any(|s| s.eq_ignore_ascii_case(&normalized)) {
		subs.push(normalized);
		write_subscriptions(data_dir, account, &subs)?;
	}
	Ok(())
}

/// Remove a subscription. Silently succeeds if not subscribed.
pub fn unsubscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let subs: Vec<String> = list_subscribed(data_dir, account)
		.into_iter()
		.filter(|s| !s.eq_ignore_ascii_case(mailbox))
		.collect();
	write_subscriptions(data_dir, account, &subs)
}

/// Subscribed mailboxes; INBOX is always subscribed.
pub fn list_subscribed(data_dir: &Path, account: &str) -> Vec<String> {
	let path = data_dir
		.join("accounts")
		.join(account)
		.join(".subscriptions");
	let mut names: Vec<String> = std::fs::read_to_string(&path)
		.unwrap_or_default()
		.lines()
		.filter(|l| !l.is_empty())
		.map(str::to_string)
		.collect();
	if !names.iter().any(|n| n.eq_ignore_ascii_case("INBOX")) {
		names.insert(0, "INBOX".to_string());
	}
	names
}

fn write_subscriptions(data_dir: &Path, account: &str, names: &[String]) -> std::io::Result<()> {
	let path = data_dir
		.join("accounts")
		.join(account)
		.join(".subscriptions");
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
