//! `mail export`: dump an account's mailboxes to mbox on stdout, for backup
//! and migration. Uses the `mboxrd` quoting (lines beginning with `From ` and
//! any run of `>`+`From ` are prefixed with `>`), so the stream round-trips.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::imap::mailbox::{self, Snapshot};

/// Write every message in `account`'s mailboxes to `out` as one mbox stream.
pub(super) fn run(data_dir: &Path, account: &str, out: &mut impl Write) -> ExitCode {
	let mut count = 0u64;
	for name in mailbox::list(data_dir, account) {
		let Ok(snapshot) = Snapshot::open(data_dir, account, &name) else {
			continue;
		};
		for message in snapshot.messages() {
			let Ok(data) = snapshot.read(message) else {
				continue;
			};
			if write_entry(out, &name, &data).is_err() {
				eprintln!("error: writing mbox stream");
				return ExitCode::FAILURE;
			}
			count += 1;
		}
	}
	if out.flush().is_err() {
		return ExitCode::FAILURE;
	}
	eprintln!("exported {count} messages for {account}");
	ExitCode::SUCCESS
}

/// One mbox entry: a `From ` separator, an `X-Mailbox` header, then the quoted
/// message body and a trailing blank line.
pub(super) fn write_entry(out: &mut impl Write, mailbox: &str, data: &[u8]) -> std::io::Result<()> {
	out.write_all(b"From MAILER-DAEMON@localhost\r\n")?;
	out.write_all(format!("X-Mailbox: {mailbox}\r\n").as_bytes())?;
	for line in split_lines(data) {
		if needs_quote(line) {
			out.write_all(b">")?;
		}
		out.write_all(line)?;
		out.write_all(b"\r\n")?;
	}
	out.write_all(b"\r\n")
}

/// Split on LF, dropping a trailing CR so we can re-emit canonical CRLF.
fn split_lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
	data.split(|&b| b == b'\n')
		.map(|line| line.strip_suffix(b"\r").unwrap_or(line))
}

/// mboxrd quoting: a line that is `From ` or `>*From ` must be `>`-prefixed.
fn needs_quote(line: &[u8]) -> bool {
	let stripped = line.iter().position(|&b| b != b'>').unwrap_or(line.len());
	line[stripped..].starts_with(b"From ")
}
