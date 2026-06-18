//! Persistent per-mailbox UIDVALIDITY (RFC 3501 §2.3.1.1).
//!
//! A constant value is written to `.uidvalidity` on first open so clients can
//! trust cached UIDs across sessions; it changes only if the mailbox is
//! recreated (the sidecar is gone).

use std::path::Path;

/// Read the mailbox's UIDVALIDITY, initializing it on first open. The value is
/// seconds-since-epoch forced odd (never 0) and persisted in `.uidvalidity`.
pub(super) fn read_or_init(account_dir: &Path) -> u32 {
	let path = account_dir.join(".uidvalidity");
	if let Ok(text) = std::fs::read_to_string(&path)
		&& let Ok(value) = text.trim().parse::<u32>()
		&& value > 0
	{
		return value;
	}
	let value = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as u32)
		.unwrap_or(1)
		| 1;
	let _ = std::fs::write(&path, value.to_string());
	value
}
