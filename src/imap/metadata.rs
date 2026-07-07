//! IMAP METADATA (RFC 5464): server- and mailbox-level annotations.
//!
//! Each annotation is an entry name (e.g. `/private/comment`) mapped to a
//! value. Mailbox annotations live in a `.metadata` sidecar beside the
//! mailbox; server annotations (mailbox name `""`) live in a `.metadata-server`
//! file at the data root. Values are stored base64-encoded, one
//! `entry base64(value)` line per annotation, so arbitrary bytes round-trip.

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::mailbox::mailbox_dir;

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
fn store_path(data_dir: &std::path::Path, account: &str, mailbox: &str) -> Option<PathBuf> {
	if mailbox.is_empty() {
		return Some(data_dir.join(".metadata-server"));
	}
	let new_dir = mailbox_dir(data_dir, account, mailbox)?;
	Some(new_dir.parent()?.join(".metadata"))
}

/// All stored annotations for a mailbox (or server level), as (entry, value).
pub fn get_all(data_dir: &std::path::Path, account: &str, mailbox: &str) -> Vec<(String, String)> {
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
pub fn get(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	entry: &str,
) -> Option<String> {
	get_all(data_dir, account, mailbox)
		.into_iter()
		.find(|(stored, _)| stored == entry)
		.map(|(_, value)| value)
}

/// Set (`Some`) or delete (`None`) an entry's value, persisting the store.
pub fn set(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	entry: &str,
	value: Option<&str>,
) -> std::io::Result<()> {
	let mut entries = get_all(data_dir, account, mailbox);
	entries.retain(|(stored, _)| stored != entry);
	if let Some(value) = value {
		entries.push((entry.to_string(), value.to_string()));
	}
	write(data_dir, account, mailbox, &entries)
}

/// Persist the annotation set, removing the file when empty.
fn write(
	data_dir: &std::path::Path,
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
	fs::write(path, body)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn set_get_roundtrip_and_delete() {
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir_all(dir.path().join("accounts").join("alice").join("new")).unwrap();
		set(
			dir.path(),
			"alice",
			"INBOX",
			"/private/comment",
			Some("hi there"),
		)
		.expect("set");
		assert_eq!(
			get(dir.path(), "alice", "INBOX", "/private/comment").as_deref(),
			Some("hi there")
		);
		set(dir.path(), "alice", "INBOX", "/private/comment", None).expect("del");
		assert_eq!(get(dir.path(), "alice", "INBOX", "/private/comment"), None);
	}

	#[test]
	fn server_level_annotations() {
		let dir = tempfile::tempdir().expect("tempdir");
		set(dir.path(), "alice", "", "/shared/vendor/x", Some("v")).expect("set");
		assert_eq!(
			get(dir.path(), "alice", "", "/shared/vendor/x").as_deref(),
			Some("v")
		);
	}

	#[test]
	fn values_with_arbitrary_bytes_roundtrip() {
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir_all(dir.path().join("accounts").join("alice").join("new")).unwrap();
		let value = "line1\nline2 with spaces";
		set(dir.path(), "alice", "INBOX", "/private/x", Some(value)).expect("set");
		assert_eq!(
			get(dir.path(), "alice", "INBOX", "/private/x").as_deref(),
			Some(value)
		);
	}

	#[test]
	fn valid_entry_rules() {
		assert!(valid_entry("/private/comment"));
		assert!(valid_entry("/shared/vendor/a"));
		assert!(!valid_entry("private/comment"));
		assert!(!valid_entry("/bad//entry"));
		assert!(!valid_entry("/has/*/star"));
		assert!(!valid_entry("/"));
	}
}
