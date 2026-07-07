//! `mail import`: migrate mail into an account. Reads either an mbox stream
//! from stdin (reverses `mail export`: `From ` separators split messages and
//! mboxrd quoting is undone) or a Maildir tree (`--maildir`), including nested
//! Dovecot Maildir++ folders.

use std::io::BufRead;
use std::path::Path;
use std::process::ExitCode;

use crate::imap::mailbox::{self, Flag};
use crate::storage::MessageCrypto;

/// Import the mbox on `reader` into `account`'s INBOX, encrypting at rest through
/// `crypto`, returning the count.
pub(super) fn run(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	reader: impl BufRead,
) -> ExitCode {
	let mut current: Option<Vec<u8>> = None;
	let mut imported = 0u64;
	let deliver = |body: Vec<u8>| {
		// Drop the trailing blank line separating mbox entries.
		let trimmed = body.strip_suffix(b"\r\n").unwrap_or(&body);
		if trimmed.is_empty() {
			return true;
		}
		mailbox::append(data_dir, account, "INBOX", &[], trimmed, crypto).is_ok()
	};
	for line in reader.lines() {
		let Ok(line) = line else {
			eprintln!("error: reading stdin");
			return ExitCode::FAILURE;
		};
		if line.starts_with("From ") {
			// A new entry begins; flush the previous one.
			if let Some(body) = current.take()
				&& deliver(body)
			{
				imported += 1;
			}
			current = Some(Vec::new());
			continue;
		}
		if let Some(body) = current.as_mut() {
			// Drop the `X-Mailbox` header our own export prepends (entry start).
			if body.is_empty() && line.starts_with("X-Mailbox:") {
				continue;
			}
			let line = unquote(&line);
			body.extend_from_slice(line.as_bytes());
			body.extend_from_slice(b"\r\n");
		}
	}
	if let Some(body) = current.take()
		&& deliver(body)
	{
		imported += 1;
	}
	eprintln!("imported {imported} messages into {account}");
	ExitCode::SUCCESS
}

/// Undo mboxrd quoting: a `>*From ` line loses one leading `>`.
fn unquote(line: &str) -> &str {
	if let Some(rest) = line.strip_prefix('>') {
		let depth = rest.bytes().take_while(|&b| b == b'>').count();
		if rest[depth..].starts_with("From ") {
			return rest;
		}
	}
	line
}

/// Import a Maildir tree into `account`. The root maildir's `cur`/`new` go to
/// INBOX; each nested Dovecot Maildir++ folder (a `.Name` / `.Parent.Child`
/// subdirectory) maps to the IMAP mailbox `Name` / `Parent.Child` (epistle uses
/// `.` as the hierarchy separator). `tmp` is ignored.
pub(super) fn run_maildir(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	maildir: &Path,
) -> ExitCode {
	// Collect every (mailbox, folder) target: INBOX at the root plus each valid
	// Maildir++ subfolder.
	let mut targets: Vec<(String, std::path::PathBuf)> =
		vec![("INBOX".to_string(), maildir.to_path_buf())];

	let entries = match std::fs::read_dir(maildir) {
		Ok(entries) => entries,
		Err(error) => {
			eprintln!("error: reading {}: {error}", maildir.display());
			return ExitCode::FAILURE;
		}
	};
	let mut folders: Vec<std::path::PathBuf> = entries
		.flatten()
		.map(|entry| entry.path())
		.filter(|path| {
			path.is_dir()
				&& path
					.file_name()
					.and_then(|n| n.to_str())
					.is_some_and(|n| n.starts_with('.') && n != "." && n != "..")
		})
		.collect();
	folders.sort();
	for folder in folders {
		let raw = folder.file_name().and_then(|n| n.to_str()).unwrap_or("");
		let name = raw.trim_start_matches('.');
		if !mailbox::valid_name(name) {
			eprintln!("warning: skipping folder \"{raw}\" (not a valid mailbox name)");
			continue;
		}
		targets.push((name.to_string(), folder));
	}

	// Import each mailbox in parallel: every target is a distinct mailbox, so
	// their UID counters and files never overlap. One scoped thread per target.
	let results: Vec<std::io::Result<u64>> = std::thread::scope(|scope| {
		let handles: Vec<_> = targets
			.iter()
			.map(|(name, folder)| {
				scope.spawn(move || import_folder(data_dir, account, name, folder, crypto))
			})
			.collect();
		handles.into_iter().map(|h| h.join().unwrap()).collect()
	});

	let mut imported = 0u64;
	for result in results {
		match result {
			Ok(count) => imported += count,
			Err(error) => {
				eprintln!("error: {error}");
				return ExitCode::FAILURE;
			}
		}
	}

	eprintln!("imported {imported} messages into {account}");
	ExitCode::SUCCESS
}

/// Append every message in a Maildir folder's `cur` and `new` to `mailbox`,
/// carrying over the Maildir info flags. Returns the count delivered.
fn import_folder(
	data_dir: &Path,
	account: &str,
	mailbox: &str,
	folder: &Path,
	crypto: &MessageCrypto,
) -> std::io::Result<u64> {
	let mut imported = 0u64;
	for sub in ["cur", "new"] {
		let Ok(entries) = std::fs::read_dir(folder.join(sub)) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if !path.is_file() {
				continue;
			}
			let data = normalize_crlf(&std::fs::read(&path)?);
			let flags = maildir_flags(&entry.file_name().to_string_lossy());
			mailbox::append(data_dir, account, mailbox, &flags, &data, crypto)?;
			imported += 1;
		}
	}
	Ok(imported)
}

/// Map Maildir info flags (`<base>:2,<flags>`) to IMAP flags. Messages in `new`
/// (no info suffix) carry none, i.e. unseen.
fn maildir_flags(filename: &str) -> Vec<Flag> {
	let Some((_, info)) = filename.split_once(":2,") else {
		return Vec::new();
	};
	let mut flags = Vec::new();
	for marker in info.chars() {
		let flag = match marker {
			'S' => Flag::Seen,
			'R' => Flag::Answered,
			'F' => Flag::Flagged,
			'T' => Flag::Deleted,
			'D' => Flag::Draft,
			_ => continue,
		};
		flags.push(flag);
	}
	flags
}

/// Normalize bare LF line endings to CRLF (Maildir files are often stored
/// LF-only; stored `.eml` and IMAP expect CRLF).
fn normalize_crlf(data: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(data.len());
	let mut prev = 0u8;
	for &byte in data {
		if byte == b'\n' && prev != b'\r' {
			out.push(b'\r');
		}
		out.push(byte);
		prev = byte;
	}
	out
}
