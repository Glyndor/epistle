//! Expunge log for QRESYNC `VANISHED (EARLIER)` (RFC 7162).
//!
//! Each expunge appends the removed UIDs and the mod-sequence at which they
//! vanished to `.vanished`, so a reconnecting client can be told which of its
//! cached UIDs are gone without re-listing the whole mailbox.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::util::path_component::{StateFile, state_file, state_tmp_file};

/// Octets the expunge log of one mailbox may hold. When an append takes the
/// log past it, the oldest entries are dropped until about half of it is
/// left, and a read looks only at the last this many octets. A client whose
/// last known mod-sequence is older than the oldest entry kept is told the
/// expunges from that entry on, not the ones before it.
pub(crate) const MAX_LOG_OCTETS: u64 = 4 * 1024 * 1024;

/// Record that `uids` vanished at `modseq`.
pub(super) fn record(account_dir: &Path, uids: &[u32], modseq: u64) -> std::io::Result<()> {
	if uids.is_empty() {
		return Ok(());
	}
	// Appends and the trimming of the log share the mailbox's mod-sequence
	// lock, so a trim never drops a line another session is appending.
	let _guard = super::modseq::lock(account_dir)?;
	let path = state_file(account_dir, StateFile::Vanished)?;
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)?;
	let mut text = String::with_capacity(uids.len() * 12);
	for uid in uids {
		text.push_str(&format!("{uid} {modseq}\n"));
	}
	file.write_all(text.as_bytes())?;
	if file.metadata()?.len() > MAX_LOG_OCTETS {
		trim(account_dir, &path)?;
	}
	Ok(())
}

/// Rewrite the log with only its newest entries, about half the cap.
fn trim(account_dir: &Path, path: &Path) -> std::io::Result<()> {
	let kept = tail(path, MAX_LOG_OCTETS / 2)?;
	let tmp = state_tmp_file(account_dir, StateFile::Vanished)?;
	std::fs::write(&tmp, kept)?;
	std::fs::rename(&tmp, path)
}

/// The last `limit` octets of the file, starting at a line boundary.
fn tail(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
	let mut file = std::fs::File::open(path)?;
	let length = file.metadata()?.len();
	let start = length.saturating_sub(limit);
	file.seek(SeekFrom::Start(start))?;
	let mut bytes = Vec::new();
	file.take(limit).read_to_end(&mut bytes)?;
	if start > 0 {
		// The first line may be cut in two: drop it.
		let cut = bytes
			.iter()
			.position(|b| *b == b'\n')
			.map_or(bytes.len(), |i| i + 1);
		bytes.drain(..cut);
	}
	Ok(bytes)
}

/// Advance the mailbox mod-sequence and log `uids` as vanished at it.
pub(super) fn record_advancing(account_dir: &Path, uids: &[u32]) {
	if uids.is_empty() {
		return;
	}
	if let Ok(modseq) = super::modseq::next_counter(account_dir) {
		let _ = record(account_dir, uids, modseq);
	}
}

/// UIDs that vanished after `modseq` (for `VANISHED (EARLIER)`), in log order.
pub(super) fn since(account_dir: &Path, modseq: u64) -> Vec<u32> {
	let Ok(bytes) =
		state_file(account_dir, StateFile::Vanished).and_then(|path| tail(&path, MAX_LOG_OCTETS))
	else {
		return Vec::new();
	};
	let text = String::from_utf8_lossy(&bytes);
	text.lines()
		.filter_map(|line| {
			let (uid, seq) = line.split_once(' ')?;
			let seq: u64 = seq.trim().parse().ok()?;
			(seq > modseq).then(|| uid.trim().parse().ok()).flatten()
		})
		.collect()
}

#[cfg(test)]
mod tests;
