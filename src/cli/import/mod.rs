//! `mail import`: migrate mail into an account. Reads either an mbox stream
//! from stdin (reverses `mail export`: `From ` separators split messages and
//! mboxrd quoting is undone) or a Maildir tree (`--maildir`), including nested
//! Dovecot Maildir++ folders.
//!
//! Every entry is bounded by the limit the server puts on what it receives
//! (`[server] max_message_size`): an entry that goes past it is refused,
//! named and counted, and the import carries on with the next one. Nothing
//! is read whole: the stream and the files are read in chunks, so the memory
//! an import takes does not grow with the size of the entry it refused.

mod maildir;
mod mbox;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;
use crate::imap::mailbox::{self, Flag};
use crate::storage::MessageCrypto;

/// An entry the import refused, and the limit it went past.
pub(super) struct Rejected {
	/// How the entry is named: `entry 3` for an mbox, the path of the file
	/// for a Maildir message.
	pub(super) name: String,
	/// The limit the entry went past.
	pub(super) limit: usize,
}

impl Rejected {
	/// An entry of an mbox that went past the limit.
	fn entry(number: u64, limit: usize) -> Self {
		Self {
			name: format!("entry {number}"),
			limit,
		}
	}

	/// A Maildir message that went past the limit.
	fn file(path: &Path, limit: usize) -> Self {
		Self {
			name: super::staging::shown(&path.display().to_string()),
			limit,
		}
	}
}

/// The largest message the import accepts: `[server] max_message_size`, or
/// the SMTP session's built-in default when the operator set none. It is the
/// same limit the server applies to what it receives.
pub(super) fn limit_from_config(config: &Config) -> usize {
	match config.max_message_size.unwrap_or(0) {
		0 => crate::smtp::session::MAX_MESSAGE_SIZE,
		size => usize::try_from(size).unwrap_or(usize::MAX),
	}
}

/// Import the mbox on `reader` into `account`'s INBOX, encrypting at rest through
/// `crypto`, returning the count. The progress line on stderr rewrites once per
/// message delivered (no-op when stderr is not a terminal).
///
/// An entry over `limit` bytes is refused: it is named, counted, and the
/// import carries on with the next one.
pub(super) fn run(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	reader: impl std::io::BufRead,
	json: bool,
	limit: usize,
	out: &mut impl Write,
) -> ExitCode {
	let mut imported = 0u64;
	let mut rejected: Vec<Rejected> = Vec::new();
	let mut progress = super::style::Progress::start("importing");
	let mut stream = mbox::Stream::new(reader);
	let mut number = 0u64;
	loop {
		let entry = match mbox::next_entry(&mut stream, limit) {
			Ok(Some(entry)) => entry,
			Ok(None) => break,
			Err(error) => {
				super::style::error(format_args!("reading stdin: {error}"));
				return ExitCode::FAILURE;
			}
		};
		number += 1;
		match entry {
			mbox::Entry::Bytes(body) => {
				if deliver(data_dir, account, crypto, &body) {
					imported += 1;
					progress.tick(imported as usize);
				}
			}
			mbox::Entry::TooBig => rejected.push(Rejected::entry(number, limit)),
		}
	}
	report(imported, rejected, account, json, progress, out)
}

/// Deliver one entry's bytes to the account's INBOX. An empty entry counts
/// as delivered: there is nothing to store.
fn deliver(data_dir: &Path, account: &str, crypto: &MessageCrypto, body: &[u8]) -> bool {
	// Drop the trailing blank line separating mbox entries.
	let trimmed = body.strip_suffix(b"\r\n").unwrap_or(body);
	if trimmed.is_empty() {
		return true;
	}
	mailbox::append(data_dir, account, "INBOX", &[], trimmed, crypto).is_ok()
}

/// Import a Maildir tree into `account`. The root maildir's `cur`/`new` go to
/// INBOX; each nested Dovecot Maildir++ folder (a `.Name` / `.Parent.Child`
/// subdirectory) maps to the IMAP mailbox `Name` / `Parent.Child` (epistle uses
/// `.` as the hierarchy separator). `tmp` is ignored.
///
/// A message over `limit` bytes is refused: it is named, counted, and the
/// rest of the folder is imported.
pub(super) fn run_maildir(
	data_dir: &Path,
	account: &str,
	crypto: &MessageCrypto,
	maildir: &Path,
	json: bool,
	limit: usize,
	out: &mut impl Write,
) -> ExitCode {
	// Collect every (mailbox, folder) target: INBOX at the root plus each valid
	// Maildir++ subfolder.
	let mut targets: Vec<(String, std::path::PathBuf)> =
		vec![("INBOX".to_string(), maildir.to_path_buf())];

	let entries = match std::fs::read_dir(maildir) {
		Ok(entries) => entries,
		Err(error) => {
			super::style::error(format_args!(
				"reading {}: {error}",
				super::staging::shown(&maildir.display().to_string())
			));
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
		let Some(name) = maildir_folder_name(raw) else {
			super::style::warn(format_args!(
				"skipping folder \"{raw}\" (not a valid mailbox name)"
			));
			continue;
		};
		targets.push((name, folder));
	}
	// Make every mailbox, parents first, before the parallel import, so two
	// threads never create the same superior.
	for (name, _) in &targets[1..] {
		if !mailbox::exists(data_dir, account, name)
			&& let Err(error) = mailbox::create(data_dir, account, name)
			&& !mailbox::exists(data_dir, account, name)
		{
			super::style::error(format_args!("creating mailbox \"{name}\": {error}"));
			return ExitCode::FAILURE;
		}
	}

	// Import each mailbox in parallel: every target is a distinct mailbox, so
	// their UID counters and files never overlap. One scoped thread per target.
	let results: Vec<std::io::Result<(u64, Vec<Rejected>)>> = std::thread::scope(|scope| {
		let handles: Vec<_> = targets
			.iter()
			.map(|(name, folder)| {
				scope.spawn(move || import_folder(data_dir, account, name, folder, crypto, limit))
			})
			.collect();
		handles.into_iter().map(|h| h.join().unwrap()).collect()
	});

	let mut imported = 0u64;
	let mut rejected: Vec<Rejected> = Vec::new();
	for result in results {
		match result {
			Ok((count, refused)) => {
				imported += count;
				rejected.extend(refused);
			}
			Err(error) => {
				super::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	}

	let mut progress = super::style::Progress::start("importing");
	progress.tick(imported as usize);
	report(imported, rejected, account, json, progress, out)
}

/// The mailbox a Maildir++ folder directory (`.Work.Project`) holds. `.` is
/// the Maildir++ hierarchy delimiter, so `.Work.Project` is `Work/Project`;
/// a name that is no valid hierarchy that way (`.Projects..2024`) keeps its
/// dots as one flat name when that is valid.
fn maildir_folder_name(raw: &str) -> Option<String> {
	let flat = raw.strip_prefix('.')?;
	let nested = flat.replace('.', "/");
	if mailbox::valid_name(&nested) {
		Some(nested)
	} else {
		mailbox::valid_name(flat).then(|| flat.to_string())
	}
}

/// Append every message in a Maildir folder's `cur` and `new` to `mailbox`,
/// carrying over the Maildir info flags. Returns the count delivered and
/// the messages that went past the limit.
fn import_folder(
	data_dir: &Path,
	account: &str,
	mailbox: &str,
	folder: &Path,
	crypto: &MessageCrypto,
	limit: usize,
) -> std::io::Result<(u64, Vec<Rejected>)> {
	let mut imported = 0u64;
	let mut rejected: Vec<Rejected> = Vec::new();
	for sub in ["cur", "new"] {
		let Ok(entries) = std::fs::read_dir(folder.join(sub)) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if !path.is_file() {
				continue;
			}
			let data = match maildir::read_message(&path, limit) {
				Ok(data) => data,
				Err(maildir::ReadError::TooBig) => {
					rejected.push(Rejected::file(&path, limit));
					continue;
				}
				Err(maildir::ReadError::Io(error)) => return Err(error),
			};
			let flags = maildir_flags(&entry.file_name().to_string_lossy());
			mailbox::append(data_dir, account, mailbox, &flags, &data, crypto)?;
			imported += 1;
		}
	}
	Ok((imported, rejected))
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

/// Report the outcome of an import: the summary on stderr, the entries it
/// refused, and the JSON result on stdout.
///
/// The exit code is the failure when an entry was refused: the import
/// finished, with errors.
fn report(
	imported: u64,
	rejected: Vec<Rejected>,
	account: &str,
	json: bool,
	progress: super::style::Progress,
	out: &mut impl Write,
) -> ExitCode {
	progress.finish(&summary(imported, rejected.len(), account));
	for entry in &rejected {
		super::style::warn(refusal(entry));
	}
	let code = imported_json(out, json, account, imported, &rejected);
	if code != ExitCode::SUCCESS {
		return code;
	}
	if rejected.is_empty() {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

/// The line that names an entry the import refused.
fn refusal(entry: &Rejected) -> String {
	format!(
		"{} is over the message size limit ({} bytes); it was not imported",
		entry.name, entry.limit
	)
}

/// The line printed once the import finished.
fn summary(imported: u64, rejected: usize, account: &str) -> String {
	if rejected == 0 {
		format!("imported {imported} messages into {account}")
	} else {
		format!(
			"imported {imported} messages into {account}, {rejected} over the message size limit"
		)
	}
}

/// With `json`, the result of an import: `{"result": "saved", "action":
/// "import", "account", "imported"}` on stdout, plus the entries the import
/// refused. The count is on stderr too, through the progress line.
fn imported_json(
	out: &mut impl Write,
	json: bool,
	account: &str,
	imported: u64,
	rejected: &[Rejected],
) -> ExitCode {
	if !json {
		return ExitCode::SUCCESS;
	}
	let result = serde_json::json!({
		"result": if imported > 0 { "saved" } else { "unchanged" },
		"action": "import", "account": account, "imported": imported,
		"rejected": rejected.len(),
		"rejected_entries": rejected
			.iter()
			.map(|entry| serde_json::json!({
				"name": entry.name, "limit": entry.limit,
			}))
			.collect::<Vec<_>>(),
	});
	super::json_out::print(out, &result)
}
