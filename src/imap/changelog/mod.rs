//! Per-account change journal behind JMAP `state` strings and `/changes`
//! (RFC 8620 sections 5.2 and 5.6).
//!
//! IMAP keeps its mod-sequences per mailbox (`.modseqctr`, `.vanished`), and
//! those cannot order two events in different mailboxes. JMAP state is
//! account-wide, so the mutation points every protocol shares (append, SMTP
//! delivery, STORE, expunge, POP3 delete, mailbox create/rename/delete) also
//! append one line per changed object to `<account>/.jmap_changes`:
//!
//! ```text
//! <position> <E|M> <C|U|D> <id>
//! ```
//!
//! Every line gets its own position, so a page of `/changes` can always end
//! between two lines and hand back a resumable intermediate state. The last
//! line's position is the account's current position. `<account>/.jmap_state`
//! holds `<epoch> <floor>`: a random epoch chosen when the journal starts (a
//! state minted for another account, or before the account was deleted and
//! re-created, never matches) and the position below which old lines were
//! trimmed. Readers and writers serialise on an `flock` of
//! `<account>/.jmap_lock`, so concurrent deliveries and IMAP sessions never
//! reuse a position and a reader never sees a half-written line.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::util::path_component::{StateFile, state_file, state_tmp_file};

/// Journal size that triggers a trim. About 20k email lines; the trim keeps
/// the newer half, and a client older than the dropped half resyncs.
const MAX_JOURNAL_BYTES: u64 = 1 << 20;

/// The kind of object a journal line is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Object {
	Email,
	Mailbox,
}

/// What happened to the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
	Created,
	Updated,
	Destroyed,
}

/// One change to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
	pub object: Object,
	pub op: Op,
	pub id: String,
}

impl Change {
	/// A change to the email `id` (its UUID).
	pub(crate) fn email(op: Op, id: uuid::Uuid) -> Self {
		Self {
			object: Object::Email,
			op,
			id: id.to_string(),
		}
	}

	/// A change to the mailbox `name`, the JMAP Mailbox id. INBOX is matched
	/// case-insensitively everywhere, so it is always recorded as `INBOX`.
	pub(crate) fn mailbox(op: Op, name: &str) -> Self {
		let id = if name.eq_ignore_ascii_case("INBOX") {
			"INBOX".to_string()
		} else {
			name.to_string()
		};
		Self {
			object: Object::Mailbox,
			op,
			id,
		}
	}
}

/// A journal line read back, with its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
	pub position: u64,
	pub change: Change,
}

/// Where the account's journal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Position {
	pub epoch: u64,
	pub current: u64,
	pub floor: u64,
}

/// Why a `since` position cannot be answered from the journal.
#[derive(Debug)]
pub(crate) enum SinceError {
	/// Another epoch, trimmed away, or ahead of the journal (a restored
	/// backup): the client has to resync.
	Unknown,
	Io(std::io::Error),
}

/// Record `changes` best-effort: a failure is logged, never returned, because
/// the mail operation it describes has already happened on disk.
pub(crate) fn note(account_root: &Path, changes: &[Change]) {
	if let Err(error) = record(account_root, changes) {
		tracing::warn!(
			%error,
			account_root = %crate::log_id::path(account_root),
			"could not record a JMAP change"
		);
	}
}

/// Append `changes` under the exclusive lock and return the new position.
pub(crate) fn record(account_root: &Path, changes: &[Change]) -> std::io::Result<u64> {
	record_with_limit(account_root, changes, MAX_JOURNAL_BYTES)
}

pub(crate) fn record_with_limit(
	account_root: &Path,
	changes: &[Change],
	max_bytes: u64,
) -> std::io::Result<u64> {
	let _guard = lock(account_root, true)?;
	let (epoch, floor) = header_or_init(account_root)?;
	let path = state_file(account_root, StateFile::JmapJournal)?;
	let mut journal = std::fs::OpenOptions::new()
		.create(true)
		.read(true)
		.append(true)
		.open(&path)?;
	let (mut position, complete_len) = last_position(&mut journal)?;
	position = position.max(floor);
	// A crash mid-append leaves a line without its newline; drop it so the
	// next line does not glue onto it.
	if journal.metadata()?.len() != complete_len {
		journal.set_len(complete_len)?;
	}
	let mut text = String::new();
	for change in changes {
		position += 1;
		text.push_str(&format_line(position, change));
	}
	journal.write_all(text.as_bytes())?;
	if journal.metadata()?.len() > max_bytes {
		trim(account_root, epoch)?;
	}
	Ok(position)
}

/// The account's current position, creating the journal header on first use.
pub(crate) fn current(account_root: &Path) -> std::io::Result<Position> {
	with_header(account_root, |epoch, floor| {
		let current = match File::open(state_file(account_root, StateFile::JmapJournal)?) {
			Ok(mut journal) => last_position(&mut journal)?.0,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
			Err(error) => return Err(error),
		};
		Ok(Position {
			epoch,
			current: current.max(floor),
			floor,
		})
	})
}

/// Every entry after `since` in `epoch`, with the position they lead to.
pub(crate) fn since(
	account_root: &Path,
	epoch: u64,
	since: u64,
) -> Result<(Position, Vec<Entry>), SinceError> {
	let read = with_header(account_root, |header_epoch, floor| {
		let path = state_file(account_root, StateFile::JmapJournal)?;
		let text = match std::fs::read_to_string(path) {
			Ok(text) => text,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
			Err(error) => return Err(error),
		};
		Ok((header_epoch, floor, text))
	});
	let (header_epoch, floor, text) = read.map_err(SinceError::Io)?;
	// Only newline-terminated lines are committed.
	let committed = text.rfind('\n').map_or("", |end| &text[..=end]);
	let entries: Vec<Entry> = committed.lines().filter_map(parse_line).collect();
	let current = entries
		.last()
		.map_or(floor, |entry| entry.position.max(floor));
	if epoch != header_epoch || since < floor || since > current {
		return Err(SinceError::Unknown);
	}
	let position = Position {
		epoch: header_epoch,
		current,
		floor,
	};
	Ok((
		position,
		entries.into_iter().filter(|e| e.position > since).collect(),
	))
}

/// Run `read` with the header under the shared lock; on first use, create the
/// header under the exclusive lock instead.
fn with_header<T>(
	account_root: &Path,
	read: impl FnOnce(u64, u64) -> std::io::Result<T>,
) -> std::io::Result<T> {
	{
		let _guard = lock(account_root, false)?;
		if let Some((epoch, floor)) = read_header(account_root) {
			return read(epoch, floor);
		}
	}
	let _guard = lock(account_root, true)?;
	let (epoch, floor) = header_or_init(account_root)?;
	read(epoch, floor)
}

fn format_line(position: u64, change: &Change) -> String {
	let object = match change.object {
		Object::Email => 'E',
		Object::Mailbox => 'M',
	};
	let op = match change.op {
		Op::Created => 'C',
		Op::Updated => 'U',
		Op::Destroyed => 'D',
	};
	format!("{position} {object} {op} {}\n", change.id)
}

fn parse_line(line: &str) -> Option<Entry> {
	let mut fields = line.splitn(4, ' ');
	let position = fields.next()?.parse().ok()?;
	let object = match fields.next()? {
		"E" => Object::Email,
		"M" => Object::Mailbox,
		_ => return None,
	};
	let op = match fields.next()? {
		"C" => Op::Created,
		"U" => Op::Updated,
		"D" => Op::Destroyed,
		_ => return None,
	};
	let id = fields.next().filter(|id| !id.is_empty())?.to_string();
	Some(Entry {
		position,
		change: Change { object, op, id },
	})
}

/// The position on the last complete line, and the length of the journal up
/// to and including that line's newline. Reads only the tail.
fn last_position(journal: &mut File) -> std::io::Result<(u64, u64)> {
	let len = journal.metadata()?.len();
	let mut window = 4096u64.min(len);
	loop {
		journal.seek(SeekFrom::Start(len - window))?;
		let mut tail = Vec::new();
		Read::take(&mut *journal, window).read_to_end(&mut tail)?;
		let Some(end) = tail.iter().rposition(|byte| *byte == b'\n') else {
			if window == len {
				return Ok((0, 0));
			}
			window = (window * 2).min(len);
			continue;
		};
		let start = tail[..end]
			.iter()
			.rposition(|byte| *byte == b'\n')
			.map(|i| i + 1);
		if start.is_none() && window < len {
			window = (window * 2).min(len);
			continue;
		}
		let line = String::from_utf8_lossy(&tail[start.unwrap_or(0)..end]);
		let position = parse_line(&line).map_or(0, |entry| entry.position);
		return Ok((position, len - window + end as u64 + 1));
	}
}

fn lock(account_root: &Path, exclusive: bool) -> std::io::Result<File> {
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(state_file(account_root, StateFile::JmapLock)?)?;
	if exclusive {
		file.lock()?;
	} else {
		file.lock_shared()?;
	}
	Ok(file)
}

/// Caller holds the exclusive lock. A journal without a header (the header
/// was lost) is discarded: positions in it can no longer be trusted, and the
/// new epoch makes every client resync once.
fn header_or_init(account_root: &Path) -> std::io::Result<(u64, u64)> {
	if let Some(header) = read_header(account_root) {
		return Ok(header);
	}
	let epoch = random_epoch()?;
	match std::fs::remove_file(state_file(account_root, StateFile::JmapJournal)?) {
		Ok(()) => {}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
		Err(error) => return Err(error),
	}
	write_header(account_root, epoch, 0)?;
	Ok((epoch, 0))
}

fn read_header(account_root: &Path) -> Option<(u64, u64)> {
	let text = state_file(account_root, StateFile::JmapState)
		.and_then(std::fs::read_to_string)
		.ok()?;
	let (epoch, floor) = text.trim().split_once(' ')?;
	Some((epoch.parse().ok()?, floor.parse().ok()?))
}

fn write_header(account_root: &Path, epoch: u64, floor: u64) -> std::io::Result<()> {
	let tmp = state_tmp_file(account_root, StateFile::JmapState)?;
	std::fs::write(&tmp, format!("{epoch} {floor}\n"))?;
	std::fs::rename(&tmp, state_file(account_root, StateFile::JmapState)?)
}

fn random_epoch() -> std::io::Result<u64> {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 8];
	ring::rand::SystemRandom::new()
		.fill(&mut bytes)
		.map_err(|_| std::io::Error::other("no randomness for the JMAP journal epoch"))?;
	Ok(u64::from_be_bytes(bytes).max(1))
}

/// Keep the newer half of the journal and raise the floor to the last
/// dropped position. Caller holds the exclusive lock.
fn trim(account_root: &Path, epoch: u64) -> std::io::Result<()> {
	let path = state_file(account_root, StateFile::JmapJournal)?;
	let text = std::fs::read_to_string(&path)?;
	let lines: Vec<&str> = text.lines().collect();
	let keep_from = lines.len() / 2;
	let Some(floor) = lines[..keep_from]
		.iter()
		.rev()
		.find_map(|line| parse_line(line))
		.map(|entry| entry.position)
	else {
		return Ok(());
	};
	let mut kept = lines[keep_from..].join("\n");
	kept.push('\n');
	let tmp = state_tmp_file(account_root, StateFile::JmapJournal)?;
	std::fs::write(&tmp, kept)?;
	// Raise the floor first: a crash between the two writes then refuses
	// positions that are still in the journal (a needless resync) rather than
	// answering from a journal that has lost lines.
	write_header(account_root, epoch, floor)?;
	std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests;
