//! IMAP METADATA (RFC 5464): server- and mailbox-level annotations.
//!
//! Each annotation is an entry name (e.g. `/private/comment`) mapped to a
//! value. Mailbox annotations live in a `.metadata` sidecar beside the
//! mailbox; server annotations (mailbox name `""`) live in a
//! `.metadata-server` file in the account's own directory, beside the
//! `.metadata` sidecar of the inbox, so every account keeps its own.
//! Values are stored base64-encoded, one `entry base64(value)` line per
//! annotation, so arbitrary bytes round-trip.
//!
//! A write takes an exclusive lock on the account's `.metadata.lock` and
//! replaces the store through a temporary file, so two sessions of the same
//! account never write over each other and a reader never sees half a
//! store.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::mailbox::mailbox_dir;
use crate::util::path_component::{AccountName, AccountRoot};

/// The sidecar of one mailbox, beside the directory holding its messages.
const MAILBOX_FILE: &str = ".metadata";

/// The file holding the server-level annotations of one account, in the
/// account's own directory. A name no mailbox and no message file can take:
/// a mailbox directory cannot start with a dot, and a message file is named
/// after the id of the message.
const SERVER_FILE: &str = ".metadata-server";

/// The file whose lock serialises the annotation writes of one account. It
/// is a file of its own, so the store is never taken for a lock.
const LOCK_FILE: &str = ".metadata.lock";

/// Whether an entry name is well-formed (RFC 5464 §3.1: slash-separated,
/// starts with `/`, no `//`, no `*`/`%` which are reserved for matching).
pub fn valid_entry(entry: &str) -> bool {
	entry.starts_with('/')
		&& !entry.contains("//")
		&& !entry.ends_with('/')
		&& !entry.contains(['*', '%'])
		&& entry.len() > 1
}

/// The annotation file for a mailbox, or the server-level file when `mailbox`
/// is empty.
fn store_path(data_dir: &Path, account: &str, mailbox: &str) -> Option<PathBuf> {
	if mailbox.is_empty() {
		return server_path(data_dir, account);
	}
	let new_dir = mailbox_dir(data_dir, account, mailbox)?;
	Some(new_dir.parent()?.join(MAILBOX_FILE))
}

/// The file holding the server-level annotations of one account: in the
/// account's own directory, so one account never reads or writes what
/// another one stored.
fn server_path(data_dir: &Path, account: &str) -> Option<PathBuf> {
	account_root(data_dir, account)?.file(SERVER_FILE).ok()
}

/// The account's own directory.
fn account_root(data_dir: &Path, account: &str) -> Option<AccountRoot> {
	AccountName::new(account).ok()?.root(data_dir).ok()
}

/// The lock that serialises the annotation writes of one account. It is
/// taken before the store is read, so a write never works from what another
/// write is replacing.
fn lock(data_dir: &Path, account: &str) -> std::io::Result<std::fs::File> {
	let root = account_root(data_dir, account)
		.ok_or_else(|| std::io::Error::other("invalid account name"))?;
	let path = root.file(LOCK_FILE)?;
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(path)?;
	file.lock()?;
	Ok(file)
}

/// All stored annotations for a mailbox (or server level), as (entry, value).
pub fn get_all(data_dir: &Path, account: &str, mailbox: &str) -> Vec<(String, String)> {
	let Some(path) = store_path(data_dir, account, mailbox) else {
		return Vec::new();
	};
	let Ok(text) = fs::read_to_string(&path) else {
		return Vec::new();
	};
	text.lines()
		.filter_map(|line| {
			let (entry, encoded) = line.split_once(' ')?;
			let value = BASE64.decode(encoded).ok()?;
			Some((
				entry.to_string(),
				String::from_utf8_lossy(&value).into_owned(),
			))
		})
		.collect()
}

/// The value of one entry, if present.
pub fn get(data_dir: &Path, account: &str, mailbox: &str, entry: &str) -> Option<String> {
	get_all(data_dir, account, mailbox)
		.into_iter()
		.find(|(stored, _)| stored == entry)
		.map(|(_, value)| value)
}

/// Set (`Some`) or delete (`None`) an entry's value, persisting the store.
pub fn set(
	data_dir: &Path,
	account: &str,
	mailbox: &str,
	entry: &str,
	value: Option<&str>,
) -> std::io::Result<()> {
	let _lock = lock(data_dir, account)?;
	let mut entries = get_all(data_dir, account, mailbox);
	entries.retain(|(stored, _)| stored != entry);
	if let Some(value) = value {
		entries.push((entry.to_string(), value.to_string()));
	}
	write(data_dir, account, mailbox, &entries)
}

/// Persist the annotation set, removing the file when empty.
fn write(
	data_dir: &Path,
	account: &str,
	mailbox: &str,
	entries: &[(String, String)],
) -> std::io::Result<()> {
	let path = store_path(data_dir, account, mailbox)
		.ok_or_else(|| std::io::Error::other("bad mailbox"))?;
	if entries.is_empty() {
		match fs::remove_file(&path) {
			Ok(()) => return Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
			Err(error) => return Err(error),
		}
	}
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let body: String = entries
		.iter()
		.map(|(entry, value)| format!("{entry} {}\n", BASE64.encode(value)))
		.collect();
	// The store is replaced through a temporary file, so a reader sees
	// either the old one or the new one, never half of it.
	let temporary = path.with_extension("tmp");
	let _ = fs::remove_file(&temporary);
	fs::write(&temporary, body)?;
	fs::rename(&temporary, &path)?;
	Ok(())
}

#[cfg(test)]
mod tests;
