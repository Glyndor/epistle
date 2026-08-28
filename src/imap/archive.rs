//! Per-account archive of expunged messages.
//!
//! When `[storage] deleted_retention_days` is set to a positive value, an
//! expunge moves the message's `.eml` and its `.flags`/`.uid` sidecars from
//! the mailbox into `<account_dir>/.archive/` instead of deleting them, and
//! drops a `<id>.deleted` sidecar next to them recording the original
//! mailbox name and the unix time of the archive. A failed move is reported
//! to the caller (who will fall back to deleting); a missing `.eml` is not
//! an error (a partially-deleted legacy message can no-op cleanly).
//!
//! Archived entries count toward the account's quota (a stored message is
//! still a stored message). The hourly sweeper ([`sweep`]) drops entries
//! whose sidecar timestamp is older than `retention_days`, and an operator
//! can list, restore, or purge them with the `epistle archive` commands or
//! the matching API routes.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::imap::mailbox;
use crate::storage::MessageCrypto;

/// The on-disk archive directory for an account: `<account_root>/.archive/`.
///
/// Every mailbox of one account shares the same archive so a deleted-message
/// recovery does not have to know which folder the message came from. The
/// caller passes the account root explicitly (rather than deriving it from
/// the mailbox directory, which has a different shape for `INBOX` than for
/// folders) so the path is unambiguous.
fn archive_dir(account_root: &Path) -> PathBuf {
	account_root.join(".archive")
}

/// The current unix time, in seconds. Centralised so the archive sidecar is
/// stamped consistently and the test path can be exercised without
/// depending on a wall clock.
fn now_unix() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// One archived message, surfaced by [`list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedMessage {
	/// The message's stable UUID (its `<id>.eml` filename stem).
	pub id: Uuid,
	/// The mailbox the message lived in when it was expunged.
	pub mailbox: String,
	/// Unix time (seconds) of the archive operation, recorded in the sidecar.
	pub deleted_at: u64,
}

/// Move `id`'s `.eml`/`.flags`/`.uid` from `mailbox_dir` into the account's
/// archive and write the `<id>.deleted` sidecar. No-op (returning `Ok(())`)
/// when the message is already gone — that is a legitimate state for a
/// partially-deleted legacy record.
///
/// `now` is the unix time stamped in the sidecar; callers compute it from
/// the wall clock in production and inject a fixed value in tests.
pub fn archive_message(
	account_root: &Path,
	mailbox_dir: &Path,
	mailbox: &str,
	id: Uuid,
	now: u64,
) -> std::io::Result<()> {
	let archive = archive_dir(account_root);
	std::fs::create_dir_all(&archive)?;
	// The sidecar is written first and the body moved last, because the body
	// is what `list` keys on: an `.eml` that reached the archive without its
	// sidecar is invisible to list, restore and purge alike, so it would sit
	// there against the account quota forever. In this order a failure at any
	// step leaves the message in its mailbox, which the caller can retry.
	let sidecar = archive.join(format!("{id}.deleted"));
	std::fs::write(sidecar, format!("{now}\n{mailbox}\n"))?;
	for ext in [".flags", ".uid", ".eml"] {
		let from = mailbox_dir.join(format!("{id}{ext}"));
		let to = archive.join(format!("{id}{ext}"));
		// A missing source file is a no-op (idempotent with concurrent
		// deletes); anything else is reported so the caller can retry.
		match std::fs::rename(&from, &to) {
			Ok(()) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
	}
	Ok(())
}

/// List every archived message for `account_root`, regardless of which
/// mailbox it came from. Returns one [`ArchivedMessage`] per `.deleted`
/// sidecar; a sidecar without the matching `.eml` is silently skipped (the
/// sweeper will have removed both).
pub fn list(account_root: &Path) -> std::io::Result<Vec<ArchivedMessage>> {
	let mut out: Vec<ArchivedMessage> = sidecars(account_root)?
		.into_iter()
		.filter(|(_, has_body)| *has_body)
		.map(|(entry, _)| entry)
		.collect();
	out.sort_by_key(|entry| entry.deleted_at);
	Ok(out)
}

/// Every readable `.deleted` sidecar under `account_root`, paired with whether
/// its message body is still present. [`list`] hides the bodiless ones because
/// they cannot be restored, but [`purge`] has to see them: a sidecar left
/// behind by a half-finished archive is reclaimed by nothing else.
fn sidecars(account_root: &Path) -> std::io::Result<Vec<(ArchivedMessage, bool)>> {
	let archive = archive_dir(account_root);
	let entries = match std::fs::read_dir(&archive) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(error) => return Err(error),
	};
	let mut out = Vec::new();
	for entry in entries.flatten() {
		let name = match entry.file_name().to_str() {
			Some(name) => name.to_string(),
			None => continue,
		};
		let Some(stem) = name.strip_suffix(".deleted") else {
			continue;
		};
		let Ok(id) = Uuid::parse_str(stem) else {
			continue;
		};
		let Ok(raw) = std::fs::read_to_string(entry.path()) else {
			continue;
		};
		let mut lines = raw.lines();
		let Some(ts_line) = lines.next() else {
			continue;
		};
		let Some(mb_line) = lines.next() else {
			continue;
		};
		let Ok(deleted_at) = ts_line.trim().parse::<u64>() else {
			continue;
		};
		let has_body = archive.join(format!("{id}.eml")).exists();
		out.push((
			ArchivedMessage {
				id,
				mailbox: mb_line.to_string(),
				deleted_at,
			},
			has_body,
		));
	}
	Ok(out)
}

/// Read the archived message identified by `id`, returning its decrypted
/// plaintext and the original mailbox name. Used by [`restore`] to re-append
/// the message with the regular mailbox pipeline.
fn read_archived(
	account_root: &Path,
	id: Uuid,
	crypto: &MessageCrypto,
) -> std::io::Result<(String, Vec<u8>)> {
	let archive = archive_dir(account_root);
	let sidecar = archive.join(format!("{id}.deleted"));
	let raw = std::fs::read_to_string(&sidecar)
		.map_err(|error| std::io::Error::other(format!("no such archived message: {error}")))?;
	let mut lines = raw.lines();
	let _ts = lines
		.next()
		.ok_or_else(|| std::io::Error::other("archived message sidecar missing timestamp"))?;
	let mailbox = lines
		.next()
		.ok_or_else(|| std::io::Error::other("archived message sidecar missing mailbox"))?;
	let stored = std::fs::read(archive.join(format!("{id}.eml")))?;
	let plaintext = crypto.decode(&stored)?;
	Ok((mailbox.to_string(), plaintext))
}

/// Restore the archived message `id` for `account`: decrypt its `.eml`,
/// re-append it to its original mailbox (falling back to `INBOX` when that
/// mailbox no longer exists), and remove every trace of it from the
/// archive. Returns the mailbox the message ended up in.
///
/// The restore goes through the regular mailbox pipeline ([`mailbox::append`])
/// so it is re-encrypted with the active at-rest key, counted toward the
/// quota, and assigned a fresh UID — the same as if it had just been
/// delivered.
pub fn restore(
	data_dir: &Path,
	account: &str,
	id: Uuid,
	crypto: &MessageCrypto,
) -> std::io::Result<String> {
	let account_root = data_dir.join("accounts").join(account);
	let (source_mailbox, plaintext) = read_archived(&account_root, id, crypto)?;
	let target = if mailbox::exists(data_dir, account, &source_mailbox) {
		source_mailbox.clone()
	} else {
		"INBOX".to_string()
	};
	mailbox::append(data_dir, account, &target, &[], &plaintext, crypto)?;
	let archive = archive_dir(&account_root);
	for ext in [".eml", ".flags", ".uid", ".deleted"] {
		let _ = std::fs::remove_file(archive.join(format!("{id}{ext}")));
	}
	Ok(target)
}

/// Delete every archived entry older than `older_than_secs` from `now`, per
/// the `<id>.deleted` sidecar timestamp. Returns the number of entries
/// purged. Entries whose sidecar cannot be parsed are kept (defensive: the
/// sweeper must not destroy data it cannot reason about).
pub fn purge(account_root: &Path, older_than_secs: u64, now: u64) -> std::io::Result<usize> {
	let archive = archive_dir(account_root);
	let mut removed = 0usize;
	// Walks the sidecars rather than `list` so an entry whose body never made
	// it into the archive is still reclaimed rather than left forever.
	for (entry, has_body) in sidecars(account_root)? {
		if now.saturating_sub(entry.deleted_at) <= older_than_secs {
			continue;
		}
		for ext in [".eml", ".flags", ".uid", ".deleted"] {
			let _ = std::fs::remove_file(archive.join(format!("{}{ext}", entry.id)));
		}
		if has_body {
			removed += 1;
		}
	}
	Ok(removed)
}

/// Hourly sweep: iterate every account under `data_dir` and purge archive
/// entries older than `retention_days` from `now`. `now` is injected so the
/// caller controls the clock — the sweeper itself never reads the wall
/// clock, which is what the test suite asserts against.
///
/// Returns the total number of entries purged across every account.
pub fn sweep(data_dir: &Path, retention_days: u64, now: u64) -> std::io::Result<u64> {
	if retention_days == 0 {
		return Ok(0);
	}
	let accounts_root = data_dir.join("accounts");
	let entries = match std::fs::read_dir(&accounts_root) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
		Err(error) => return Err(error),
	};
	let retention_secs = retention_days.saturating_mul(86_400);
	let mut removed = 0u64;
	for entry in entries.flatten() {
		let path = entry.path();
		if !path.is_dir() {
			continue;
		}
		let removed_here = purge(&path, retention_secs, now)?;
		removed = removed.saturating_add(u64::try_from(removed_here).unwrap_or(u64::MAX));
	}
	Ok(removed)
}

/// The current unix time, exposed so callers that already have a snapshot
/// (`Snapshot::now_unix`) can stamp the sidecar with the same value rather
/// than sampling the clock twice.
pub fn current_unix_time() -> u64 {
	now_unix()
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
