//! `mail verify`: check on-disk data integrity before an upgrade. Walks every
//! account's mailbox directories and reports any unreadable, malformed, or
//! orphaned files without modifying anything. Exits non-zero if problems exist.

use std::path::Path;
use std::process::ExitCode;

use crate::imap::mailbox::{self, Flag};
use crate::storage::MessageCrypto;

/// Run the integrity check over `data_dir`, writing a report to `out`. Message
/// files are decoded through `crypto` so an encrypted store validates against the
/// plaintext, not the envelope.
pub(super) fn run(
	data_dir: &Path,
	crypto: &MessageCrypto,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let accounts_dir = data_dir.join("accounts");
	let Ok(entries) = std::fs::read_dir(&accounts_dir) else {
		let _ = writeln!(out, "no accounts directory at {}", accounts_dir.display());
		return ExitCode::SUCCESS;
	};

	let mut accounts = 0u64;
	let mut messages = 0u64;
	let mut problems: Vec<String> = Vec::new();

	let mut account_names: Vec<String> = entries
		.flatten()
		.filter(|entry| entry.path().is_dir())
		.filter_map(|entry| entry.file_name().into_string().ok())
		.collect();
	account_names.sort();

	for account in &account_names {
		accounts += 1;
		// `mailbox::list` already includes INBOX plus every folder.
		for mailbox_name in mailbox::list(data_dir, account) {
			let Some(dir) = mailbox::mailbox_dir(data_dir, account, &mailbox_name) else {
				continue;
			};
			check_mailbox(
				&dir,
				account,
				&mailbox_name,
				crypto,
				&mut messages,
				&mut problems,
			);
		}
	}

	for problem in &problems {
		let _ = writeln!(out, "problem: {problem}");
	}
	let _ = writeln!(
		out,
		"checked {accounts} accounts, {messages} messages: {} problems",
		problems.len()
	);
	if problems.is_empty() {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

/// Validate every `.eml` and `.flags` file in one mailbox directory.
fn check_mailbox(
	dir: &Path,
	account: &str,
	mailbox: &str,
	crypto: &MessageCrypto,
	messages: &mut u64,
	problems: &mut Vec<String>,
) {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return;
	};
	let mut ids = std::collections::HashSet::new();
	let mut flag_files = Vec::new();
	for entry in entries.flatten() {
		let path = entry.path();
		let name = entry.file_name().to_string_lossy().into_owned();
		let here = format!("{account}/{mailbox}/{name}");
		if let Some(stem) = name.strip_suffix(".eml") {
			if uuid::Uuid::parse_str(stem).is_err() {
				problems.push(format!("{here}: filename is not a UUID"));
				continue;
			}
			ids.insert(stem.to_string());
			*messages += 1;
			match std::fs::read(&path).and_then(|stored| crypto.decode(&stored)) {
				Ok(data) if data.is_empty() => problems.push(format!("{here}: empty message")),
				Ok(data) if !has_header_separator(&data) => {
					problems.push(format!("{here}: no header/body separator"));
				}
				Ok(_) => {}
				Err(error) => problems.push(format!("{here}: unreadable ({error})")),
			}
		} else if let Some(stem) = name.strip_suffix(".flags") {
			flag_files.push((stem.to_string(), path, here));
		}
	}
	// Flags must parse and reference an existing message in the same mailbox.
	for (stem, path, here) in flag_files {
		if !ids.contains(&stem) {
			problems.push(format!("{here}: orphaned flags (no matching message)"));
			continue;
		}
		match std::fs::read(&path) {
			Ok(bytes) => {
				if serde_json::from_slice::<Vec<Flag>>(&bytes).is_err() {
					problems.push(format!("{here}: malformed flags file"));
				}
			}
			Err(error) => problems.push(format!("{here}: unreadable flags ({error})")),
		}
	}
}

/// Whether the message has a header/body separator (a blank line). Accepts both
/// CRLF and bare-LF forms defensively.
fn has_header_separator(data: &[u8]) -> bool {
	data.windows(4).any(|w| w == b"\r\n\r\n") || data.windows(2).any(|w| w == b"\n\n")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn clean_store_reports_no_problems() {
		let dir = tempfile::tempdir().expect("tempdir");
		mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[Flag::Seen],
			b"Subject: x\r\n\r\nbody",
			&MessageCrypto::disabled(),
		)
		.expect("append");
		mailbox::append(
			dir.path(),
			"alice",
			"Archive",
			&[],
			b"Subject: y\r\n\r\nbody",
			&MessageCrypto::disabled(),
		)
		.expect("append");
		let mut out = Vec::new();
		assert_eq!(
			run(dir.path(), &MessageCrypto::disabled(), &mut out),
			ExitCode::SUCCESS
		);
		let report = String::from_utf8(out).expect("utf8");
		assert!(report.contains("2 messages: 0 problems"), "{report}");
	}

	#[test]
	fn detects_bad_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		let inbox = dir.path().join("accounts").join("alice").join("new");
		std::fs::create_dir_all(&inbox).expect("mkdir");
		// Non-UUID filename.
		std::fs::write(inbox.join("not-a-uuid.eml"), b"Subject: x\r\n\r\nb").expect("write");
		// Valid UUID but no header/body separator.
		let bad = uuid::Uuid::now_v7();
		std::fs::write(inbox.join(format!("{bad}.eml")), b"no separator here").expect("write");
		// Orphaned flags (no matching message).
		let orphan = uuid::Uuid::now_v7();
		std::fs::write(inbox.join(format!("{orphan}.flags")), b"[\"\\\\Seen\"]").expect("write");

		let mut out = Vec::new();
		assert_eq!(
			run(dir.path(), &MessageCrypto::disabled(), &mut out),
			ExitCode::FAILURE
		);
		let report = String::from_utf8(out).expect("utf8");
		assert!(report.contains("not a UUID"), "{report}");
		assert!(report.contains("no header/body separator"), "{report}");
		assert!(report.contains("orphaned flags"), "{report}");
	}

	#[test]
	fn missing_accounts_dir_is_ok() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut out = Vec::new();
		assert_eq!(
			run(dir.path(), &MessageCrypto::disabled(), &mut out),
			ExitCode::SUCCESS
		);
	}
}
