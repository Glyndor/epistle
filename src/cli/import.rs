//! `mail import`: read an mbox stream from stdin and deliver each message into
//! an account's INBOX, for migration onto the server. Reverses `mail export`:
//! `From ` separator lines split messages and mboxrd quoting is undone.

use std::io::BufRead;
use std::path::Path;
use std::process::ExitCode;

use crate::imap::mailbox;

/// Import the mbox on `reader` into `account`'s INBOX, returning the count.
pub(super) fn run(data_dir: &Path, account: &str, reader: impl BufRead) -> ExitCode {
	let mut current: Option<Vec<u8>> = None;
	let mut imported = 0u64;
	let deliver = |body: Vec<u8>| {
		// Drop the trailing blank line separating mbox entries.
		let trimmed = body.strip_suffix(b"\r\n").unwrap_or(&body);
		if trimmed.is_empty() {
			return true;
		}
		mailbox::append(data_dir, account, "INBOX", &[], trimmed).is_ok()
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
