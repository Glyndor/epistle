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
// Consumed by the QRESYNC SELECT path (added next); exercised by tests now.
#[allow(dead_code)]
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
