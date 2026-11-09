//! `mail export`: dump an account's mailboxes to mbox on stdout, for backup
//! and migration. Uses the `mboxrd` quoting (lines beginning with `From ` and
//! any run of `>`+`From ` are prefixed with `>`), so the stream round-trips.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::storage::MessageCrypto;

/// The line printed once an export finished.
pub(super) fn exported_summary(count: u64) -> String {
	format!("exported {count} messages")
}

/// Write every message in `account`'s mailboxes to `out` as one mbox stream,
/// decoding any at-rest encryption through `crypto`.
pub(super) fn run(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	out: &mut impl Write,
) -> ExitCode {
	let _warnings = crate::util::fs_walk::warning_scope();
	let mut count = 0u64;
	for name in mailbox::list(data_dir, account) {
		let Ok(snapshot) = Snapshot::open(data_dir, account, &name, crypto) else {
			continue;
		};
		for message in snapshot.messages() {
			let Ok(data) = snapshot.read(message) else {
				continue;
			};
			if write_entry(out, &name, &data).is_err() {
				super::style::error("writing mbox stream");
				return ExitCode::FAILURE;
			}
			count += 1;
		}
	}
	if out.flush().is_err() {
		return ExitCode::FAILURE;
	}
	super::term::live::quiet(|| eprintln!("{}", exported_summary(count)));
	ExitCode::SUCCESS
}

/// Export `account`'s mailboxes to a Maildir tree under `dir`: INBOX to the
/// root `cur/`, each other mailbox to a Dovecot Maildir++ `.Name/cur/`
/// subdirectory, a subfolder as `.Parent.Name/cur/` (the inverse of the
/// Maildir import). A `.` inside a level is read back by the import as a
/// level of its own, which Maildir++ cannot tell apart. IMAP flags are carried in
/// the Maildir `:2,<info>` filename suffix.
pub(super) fn run_maildir(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	dir: &Path,
) -> ExitCode {
	let _warnings = crate::util::fs_walk::warning_scope();
	let mut count = 0u64;
	for name in mailbox::list(data_dir, account) {
		// Maildir++ writes the hierarchy with `.`: `Work/Project` is
		// `.Work.Project`, one directory like every other folder.
		let folder = if name.eq_ignore_ascii_case("INBOX") {
			dir.to_path_buf()
		} else {
			dir.join(format!(".{}", name.replace('/', ".")))
		};
		let cur = folder.join("cur");
		if private_dirs(&cur).is_err() {
			super::style::error(format_args!(
				"creating {}",
				super::staging::shown(&cur.display().to_string())
			));
			return ExitCode::FAILURE;
		}
		let Ok(snapshot) = Snapshot::open(data_dir, account, &name, crypto) else {
			continue;
		};
		for message in snapshot.messages() {
			let Ok(data) = snapshot.read(message) else {
				continue;
			};
			let filename = format!("{}:2,{}", message.id(), maildir_flags(&message.flags));
			if write_private(&cur.join(filename), &data).is_err() {
				super::style::error(format_args!(
					"writing message to {}",
					super::staging::shown(&cur.display().to_string())
				));
				return ExitCode::FAILURE;
			}
			count += 1;
		}
	}
	super::term::live::quiet(|| eprintln!("{}", exported_summary(count)));
	ExitCode::SUCCESS
}

/// The Maildir info flags (`:2,` suffix) for a message's IMAP flags, in the
/// canonical alphabetical order (RFC-less Maildir convention).
fn maildir_flags(flags: &[Flag]) -> String {
	let mut info = String::new();
	for (flag, ch) in [
		(Flag::Draft, 'D'),
		(Flag::Flagged, 'F'),
		(Flag::Answered, 'R'),
		(Flag::Seen, 'S'),
		(Flag::Deleted, 'T'),
	] {
		if flags.contains(&flag) {
			info.push(ch);
		}
	}
	info
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

/// `path` and the directories above it that do not exist yet, owner only: the
/// export holds decrypted mail, so it is not given more access than the store
/// it came from.
fn private_dirs(path: &Path) -> std::io::Result<()> {
	use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
	std::fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(path)?;
	// The mode above only applies to what was created: a directory left by an
	// earlier export keeps its own, so it is set here as well.
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Write `data` to `path` readable by the owner only.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
	use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o600)
		.open(path)?;
	// Same as for the directories: a file that was already there keeps its mode
	// through `open`, so it is set on the handle before the mail is written.
	file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
	file.write_all(data)
}

#[cfg(test)]
mod tests;
