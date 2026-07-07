//! `mail export`: dump an account's mailboxes to mbox on stdout, for backup
//! and migration. Uses the `mboxrd` quoting (lines beginning with `From ` and
//! any run of `>`+`From ` are prefixed with `>`), so the stream round-trips.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::storage::MessageCrypto;

/// Write every message in `account`'s mailboxes to `out` as one mbox stream,
/// decoding any at-rest encryption through `crypto`.
pub(super) fn run(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	out: &mut impl Write,
) -> ExitCode {
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

/// Export `account`'s mailboxes to a Maildir tree under `dir`: INBOX to the
/// root `cur/`, each other mailbox to a Dovecot Maildir++ `.Name/cur/`
/// subdirectory (the inverse of the Maildir import). IMAP flags are carried in
/// the Maildir `:2,<info>` filename suffix.
pub(super) fn run_maildir(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	dir: &Path,
) -> ExitCode {
	let mut count = 0u64;
	for name in mailbox::list(data_dir, account) {
		let folder = if name.eq_ignore_ascii_case("INBOX") {
			dir.to_path_buf()
		} else {
			dir.join(format!(".{name}"))
		};
		let cur = folder.join("cur");
		if std::fs::create_dir_all(&cur).is_err() {
			eprintln!("error: creating {}", cur.display());
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
			if std::fs::write(cur.join(filename), &data).is_err() {
				eprintln!("error: writing message to {}", cur.display());
				return ExitCode::FAILURE;
			}
			count += 1;
		}
	}
	eprintln!("exported {count} messages for {account}");
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

#[cfg(test)]
mod tests {
	use super::*;

	/// Write a raw message into an account's INBOX (`new`).
	fn deliver(data_dir: &Path, account: &str, body: &[u8]) {
		let new_dir = data_dir.join("accounts").join(account).join("new");
		std::fs::create_dir_all(&new_dir).expect("dirs");
		let id = uuid::Uuid::now_v7();
		std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
	}

	#[test]
	fn export_decrypts_encrypted_store_to_plaintext_mbox() {
		// With encryption on, the on-disk message is ciphertext but the exported
		// mbox stream must carry the plaintext.
		let dir = tempfile::tempdir().expect("tempdir");
		let crypto = MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");
		mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			b"Subject: hi\r\n\r\nsecret export body\r\n",
			&crypto,
		)
		.expect("append");
		// The stored file is encrypted.
		let new_dir = dir.path().join("accounts").join("alice").join("new");
		let stored = std::fs::read_dir(&new_dir)
			.expect("new dir")
			.flatten()
			.map(|e| std::fs::read(e.path()).expect("read"))
			.next()
			.expect("one file");
		assert!(
			stored.starts_with(b"EPENC1\0"),
			"stored message is encrypted"
		);

		let mut out = Vec::new();
		assert_eq!(
			run(dir.path(), "alice", &crypto, &mut out),
			ExitCode::SUCCESS
		);
		let text = String::from_utf8(out).expect("utf8");
		assert!(text.contains("secret export body"), "{text}");
	}

	#[test]
	fn maildir_flags_are_canonical_order() {
		let flags = [Flag::Seen, Flag::Draft, Flag::Answered];
		// Output is always D F R S T order regardless of input order.
		assert_eq!(maildir_flags(&flags), "DRS");
		assert_eq!(maildir_flags(&[]), "");
		assert_eq!(maildir_flags(&[Flag::Deleted, Flag::Flagged]), "FT");
	}

	#[test]
	fn maildir_export_writes_messages_to_cur() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"Subject: one\r\n\r\nbody one\r\n");
		deliver(dir.path(), "alice", b"Subject: two\r\n\r\nbody two\r\n");

		let out = tempfile::tempdir().expect("out");
		assert_eq!(
			run_maildir(dir.path(), "alice", &MessageCrypto::disabled(), out.path()),
			ExitCode::SUCCESS
		);
		let cur = out.path().join("cur");
		let files: Vec<_> = std::fs::read_dir(&cur)
			.expect("cur exists")
			.flatten()
			.collect();
		assert_eq!(files.len(), 2, "two messages exported");
		// Maildir filenames carry the `:2,` info suffix.
		assert!(
			files
				.iter()
				.all(|f| f.file_name().to_string_lossy().contains(":2,")),
			"maildir info suffix present"
		);
	}

	#[test]
	fn maildir_export_round_trips_through_import() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"Subject: hello\r\n\r\nround trip\r\n");

		let out = tempfile::tempdir().expect("out");
		assert_eq!(
			run_maildir(dir.path(), "alice", &MessageCrypto::disabled(), out.path()),
			ExitCode::SUCCESS
		);

		// Import the exported Maildir into a fresh account and confirm the
		// message survives.
		let dest = tempfile::tempdir().expect("dest");
		assert_eq!(
			crate::cli::import::run_maildir(
				dest.path(),
				"bob",
				&MessageCrypto::disabled(),
				out.path()
			),
			ExitCode::SUCCESS
		);
		let snapshot =
			Snapshot::open(dest.path(), "bob", "INBOX", &MessageCrypto::disabled()).expect("inbox");
		assert_eq!(snapshot.messages().count(), 1);
		let message = snapshot.messages().next().expect("message");
		let data = snapshot.read(message).expect("read");
		assert!(
			String::from_utf8_lossy(&data).contains("round trip"),
			"content preserved"
		);
	}
}
