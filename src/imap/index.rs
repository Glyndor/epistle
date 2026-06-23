//! Per-mailbox metadata index: a rebuildable, on-disk read-acceleration cache
//! for [`super::mailbox::Snapshot::open`].
//!
//! The filesystem (`.eml` files plus their `.uid`/`.flags`/`.modseq` sidecars)
//! is the canonical source of truth. This index caches the per-message metadata
//! that `Snapshot::open` would otherwise gather by reading several sidecars per
//! message — turning an O(mailbox size) burst of small reads into a single
//! sequential read of one compact file.
//!
//! ## Why an index (issue #236, follows the #235 profiling pass)
//!
//! The macro profiler ([`examples/profile.rs`], issue #235) showed
//! `Snapshot::open` is the cost that scales with mailbox size: per message it
//! opens the `.flags`, `.uid`, `.modseq` sidecars and calls `metadata()`. The
//! index folds all of that into one file read.
//!
//! ## Fail closed
//!
//! A missing, unreadable, unparseable, wrong-version, or stale index is treated
//! as absent: the caller falls back to the authoritative filesystem scan and
//! rebuilds the index. A corrupt index can therefore never yield wrong mailbox
//! contents — when in any doubt the scan wins.
//!
//! ## Write amplification
//!
//! The index is written only on a rebuild, never per mutation. Flag changes
//! keep writing just the `.flags` sidecar and bump the mailbox mod-sequence;
//! the index simply goes stale (its stamp no longer matches the current
//! generation) and is rebuilt on the next open that needs it.
//!
//! ## Format (version 1)
//!
//! A UTF-8 text file, one record per line, fields separated by a single space:
//!
//! ```text
//! EPISTLE-MAILBOX-INDEX 1
//! gen <highest_modseq> <message_count>
//! <uuid> <uid> <plaintext_size> <internaldate_secs>.<nanos> <modseq> <flag,flag,...>
//! ...
//! ```
//!
//! Line 1 is the magic + format version; an unknown version is ignored. Line 2
//! is the generation stamp: the mailbox's highest mod-sequence and the `.eml`
//! file count at build time. The remaining lines are the message records in the
//! same sequence order `Snapshot::open` produces (UUID-sorted). Flags are the
//! lowercase wire tokens without the leading backslash, comma-joined; an empty
//! flag set is a trailing empty field.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::mailbox::{Flag, MessageRef};

/// Index file name inside a mailbox `new/` directory.
const FILE_NAME: &str = ".index";

/// Magic header identifying the file and its line format.
const MAGIC: &str = "EPISTLE-MAILBOX-INDEX";

/// Current on-disk format version. A file with any other version is ignored.
const VERSION: u32 = 1;

/// The path of a mailbox's index file.
fn index_path(account_dir: &Path) -> PathBuf {
	account_dir.join(FILE_NAME)
}

/// The current mailbox generation: its highest mod-sequence and `.eml` count.
///
/// Both are cheap: the mod-sequence is the persisted `.modseqctr` counter (one
/// small read) and the count is a single `read_dir` pass with no per-file work.
/// A mismatch on either field versus the stored stamp means the index is stale.
pub(super) fn current_generation(account_dir: &Path) -> (u64, usize) {
	let modseq = super::modseq::read_counter(account_dir).max(1);
	let count = match std::fs::read_dir(account_dir) {
		Ok(entries) => entries
			.flatten()
			.filter(|entry| {
				entry
					.file_name()
					.to_str()
					.is_some_and(|name| name.ends_with(".eml"))
			})
			.count(),
		Err(_) => 0,
	};
	(modseq, count)
}

/// Load the index if it exists, parses cleanly, has the current version, and its
/// stamp matches `generation`. Any deviation returns `None` so the caller falls
/// back to the authoritative filesystem scan (fail closed).
pub(super) fn load(account_dir: &Path, generation: (u64, usize)) -> Option<Vec<MessageRef>> {
	let text = std::fs::read_to_string(index_path(account_dir)).ok()?;
	let mut lines = text.lines();

	// Header: magic + version.
	let header = lines.next()?;
	let (magic, version) = header.split_once(' ')?;
	if magic != MAGIC || version.parse::<u32>().ok()? != VERSION {
		return None;
	}

	// Generation stamp.
	let stamp = lines.next()?;
	let mut stamp_fields = stamp.split(' ');
	if stamp_fields.next()? != "gen" {
		return None;
	}
	let stamp_modseq: u64 = stamp_fields.next()?.parse().ok()?;
	let stamp_count: usize = stamp_fields.next()?.parse().ok()?;
	if (stamp_modseq, stamp_count) != generation {
		return None;
	}

	// Records. A single malformed record invalidates the whole index.
	let mut messages = Vec::with_capacity(stamp_count);
	for line in lines {
		messages.push(parse_record(line)?);
	}
	// The record count must agree with the stamp, or the file is truncated.
	if messages.len() != stamp_count {
		return None;
	}
	Some(messages)
}

/// Parse one record line into a [`MessageRef`], or `None` on any malformation.
fn parse_record(line: &str) -> Option<MessageRef> {
	let mut fields = line.split(' ');
	let id = Uuid::parse_str(fields.next()?).ok()?;
	let uid: u32 = fields.next()?.parse().ok()?;
	let size: u64 = fields.next()?.parse().ok()?;
	let internal_date = parse_time(fields.next()?)?;
	let modseq: u64 = fields.next()?.parse().ok()?;
	// The flags field is the remainder (it never contains a space): present even
	// when empty. A missing field (too few columns) is a malformed record.
	let flags = parse_flags(fields.next()?)?;
	// Any extra column means a format we do not understand: fail closed.
	if fields.next().is_some() {
		return None;
	}
	Some(MessageRef::from_index(
		uid,
		id,
		size,
		flags,
		internal_date,
		modseq,
	))
}

/// Parse the `<secs>.<nanos>` internaldate field into a [`SystemTime`].
fn parse_time(field: &str) -> Option<SystemTime> {
	let (secs, nanos) = field.split_once('.')?;
	let secs: u64 = secs.parse().ok()?;
	let nanos: u32 = nanos.parse().ok()?;
	if nanos >= 1_000_000_000 {
		return None;
	}
	Some(UNIX_EPOCH + Duration::new(secs, nanos))
}

/// Parse the comma-joined flag field. An empty field is the empty flag set; an
/// unrecognized flag token fails closed (the writer only emits known tokens, so
/// an unknown one signals corruption or a format drift).
fn parse_flags(field: &str) -> Option<Vec<Flag>> {
	if field.is_empty() {
		return Some(Vec::new());
	}
	field
		.split(',')
		.map(|token| Flag::parse(&format!("\\{token}")))
		.collect()
}

/// Write a fresh index for `messages`, stamped with `generation`, atomically
/// (temp file + rename). A write failure is reported to the caller but must not
/// fail the open — the snapshot already succeeded from the scan.
pub(super) fn write(
	account_dir: &Path,
	generation: (u64, usize),
	messages: &[MessageRef],
) -> std::io::Result<()> {
	let mut out = String::with_capacity(64 + messages.len() * 64);
	out.push_str(MAGIC);
	out.push(' ');
	out.push_str(&VERSION.to_string());
	out.push('\n');
	out.push_str("gen ");
	out.push_str(&generation.0.to_string());
	out.push(' ');
	out.push_str(&generation.1.to_string());
	out.push('\n');
	for message in messages {
		write_record(&mut out, message);
	}

	let tmp = account_dir.join(format!("{FILE_NAME}.tmp"));
	std::fs::write(&tmp, out.as_bytes())?;
	std::fs::rename(&tmp, index_path(account_dir))
}

/// Append one record line to `out`, mirroring [`parse_record`].
fn write_record(out: &mut String, message: &MessageRef) {
	out.push_str(&message.id().to_string());
	out.push(' ');
	out.push_str(&message.uid.to_string());
	out.push(' ');
	out.push_str(&message.size.to_string());
	out.push(' ');
	write_time(out, message.internal_date);
	out.push(' ');
	out.push_str(&message.modseq.to_string());
	out.push(' ');
	for (index, flag) in message.flags.iter().enumerate() {
		if index > 0 {
			out.push(',');
		}
		// The wire token without its leading backslash (e.g. "seen").
		out.push_str(&flag.as_str()[1..].to_ascii_lowercase());
	}
	out.push('\n');
}

/// Write a [`SystemTime`] as `<secs>.<nanos>` since the Unix epoch.
fn write_time(out: &mut String, time: SystemTime) {
	let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
	out.push_str(&since.as_secs().to_string());
	out.push('.');
	out.push_str(&since.subsec_nanos().to_string());
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;
