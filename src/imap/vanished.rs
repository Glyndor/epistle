//! Expunge log for QRESYNC `VANISHED (EARLIER)` (RFC 7162).
//!
//! Each expunge appends the removed UIDs and the mod-sequence at which they
//! vanished to `.vanished`, so a reconnecting client can be told which of its
//! cached UIDs are gone without re-listing the whole mailbox.

use std::path::Path;

/// Record that `uids` vanished at `modseq`.
pub(super) fn record(account_dir: &Path, uids: &[u32], modseq: u64) -> std::io::Result<()> {
	if uids.is_empty() {
		return Ok(());
	}
	use std::io::Write;
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(account_dir.join(".vanished"))?;
	for uid in uids {
		writeln!(file, "{uid} {modseq}")?;
	}
	Ok(())
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
	let Ok(text) = std::fs::read_to_string(account_dir.join(".vanished")) else {
		return Vec::new();
	};
	text.lines()
		.filter_map(|line| {
			let (uid, seq) = line.split_once(' ')?;
			let seq: u64 = seq.trim().parse().ok()?;
			(seq > modseq).then(|| uid.trim().parse().ok()).flatten()
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn records_and_queries_vanished_uids() {
		let dir = tempfile::tempdir().expect("tempdir");
		// No log yet → nothing vanished.
		assert!(since(dir.path(), 0).is_empty());
		// An empty set is a no-op (no file created).
		record(dir.path(), &[], 5).expect("noop");
		assert!(since(dir.path(), 0).is_empty());

		record(dir.path(), &[1, 2], 10).expect("record");
		record(dir.path(), &[3], 20).expect("record");
		// Everything after modseq 0.
		assert_eq!(since(dir.path(), 0), vec![1, 2, 3]);
		// Only the later expunge after modseq 10.
		assert_eq!(since(dir.path(), 10), vec![3]);
		// Nothing after the highest modseq.
		assert!(since(dir.path(), 20).is_empty());
	}

	#[test]
	fn record_advancing_assigns_a_modseq() {
		let dir = tempfile::tempdir().expect("tempdir");
		record_advancing(dir.path(), &[7]);
		// The uid is logged at some positive mod-sequence.
		assert_eq!(since(dir.path(), 0), vec![7]);
		// An empty set advances nothing.
		record_advancing(dir.path(), &[]);
		assert_eq!(since(dir.path(), 0), vec![7]);
	}
}
