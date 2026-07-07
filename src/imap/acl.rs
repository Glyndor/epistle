//! IMAP Access Control Lists (RFC 4314).
//!
//! Per-mailbox rights for identifiers, stored one `identifier rights` line per
//! entry in an `.acl` sidecar beside the mailbox. The mailbox owner (the
//! account itself) implicitly holds [`ALL_RIGHTS`] and is never stored, so an
//! ACL can never lock the owner out — administer rights cannot be revoked from
//! the owner.

use std::fs;
use std::path::PathBuf;

use super::mailbox::mailbox_dir;

/// The full RFC 4314 rights set the server recognises and grants the owner:
/// lookup, read, seen, write, insert, post, create, delete-messages,
/// delete-mailbox, expunge, administer.
pub const ALL_RIGHTS: &str = "lrswipkxtea";

/// The ACL sidecar path for a mailbox (beside it, not inside `new/`).
fn acl_path(data_dir: &std::path::Path, account: &str, mailbox: &str) -> Option<PathBuf> {
	let new_dir = mailbox_dir(data_dir, account, mailbox)?;
	Some(new_dir.parent()?.join(".acl"))
}

/// Whether every character of `rights` is a recognised RFC 4314 right.
pub fn valid_rights(rights: &str) -> bool {
	rights.chars().all(|c| ALL_RIGHTS.contains(c))
}

/// Canonicalise a rights string to [`ALL_RIGHTS`] order with duplicates
/// removed, so stored and reported rights are stable.
fn canonical(rights: &str) -> String {
	ALL_RIGHTS.chars().filter(|c| rights.contains(*c)).collect()
}

/// Read the stored ACL entries (identifier, rights) for a mailbox, in file
/// order. The owner is not included.
pub fn get(data_dir: &std::path::Path, account: &str, mailbox: &str) -> Vec<(String, String)> {
	let Some(path) = acl_path(data_dir, account, mailbox) else {
		return Vec::new();
	};
	let Ok(text) = fs::read_to_string(&path) else {
		return Vec::new();
	};
	text.lines()
		.filter_map(|line| {
			let (id, rights) = line.split_once(' ')?;
			if id.is_empty() || rights.is_empty() {
				return None;
			}
			Some((id.to_string(), rights.to_string()))
		})
		.collect()
}

/// The rights an identifier holds on a mailbox: the owner always holds
/// [`ALL_RIGHTS`]; any other identifier holds only what is stored (empty if
/// none) — fail closed.
pub fn rights_of(data_dir: &std::path::Path, account: &str, mailbox: &str, id: &str) -> String {
	if id == account {
		return ALL_RIGHTS.to_string();
	}
	get(data_dir, account, mailbox)
		.into_iter()
		.find(|(stored, _)| stored == id)
		.map(|(_, rights)| rights)
		.unwrap_or_default()
}

/// Set (replacing) the rights for an identifier. A `+`/`-` prefix adds or
/// removes the listed rights relative to the current set; otherwise the set is
/// replaced. Removing all rights deletes the entry. The owner cannot be
/// modified. Returns the resulting rights string.
pub fn set(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	id: &str,
	mod_rights: &str,
) -> std::io::Result<String> {
	if id == account {
		// The owner's rights are immutable; report them unchanged.
		return Ok(ALL_RIGHTS.to_string());
	}
	let (op, body) = match mod_rights.strip_prefix(['+', '-']) {
		Some(body) => (mod_rights.as_bytes()[0], body),
		None => (b'=', mod_rights),
	};
	let mut entries = get(data_dir, account, mailbox);
	let current = entries
		.iter()
		.find(|(stored, _)| stored == id)
		.map(|(_, r)| r.clone())
		.unwrap_or_default();
	let next: String = match op {
		b'+' => canonical(&format!("{current}{body}")),
		b'-' => current.chars().filter(|c| !body.contains(*c)).collect(),
		_ => canonical(body),
	};
	entries.retain(|(stored, _)| stored != id);
	if !next.is_empty() {
		entries.push((id.to_string(), next.clone()));
	}
	write(data_dir, account, mailbox, &entries)?;
	Ok(next)
}

/// Remove an identifier's ACL entry entirely. The owner cannot be removed.
pub fn delete(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	id: &str,
) -> std::io::Result<()> {
	if id == account {
		return Ok(());
	}
	let mut entries = get(data_dir, account, mailbox);
	entries.retain(|(stored, _)| stored != id);
	write(data_dir, account, mailbox, &entries)
}

/// Persist the ACL entries for a mailbox, replacing the sidecar atomically.
fn write(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
	entries: &[(String, String)],
) -> std::io::Result<()> {
	let path =
		acl_path(data_dir, account, mailbox).ok_or_else(|| std::io::Error::other("bad mailbox"))?;
	if entries.is_empty() {
		match fs::remove_file(&path) {
			Ok(()) => return Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
			Err(error) => return Err(error),
		}
	}
	let body: String = entries
		.iter()
		.map(|(id, rights)| format!("{id} {rights}\n"))
		.collect();
	fs::write(path, body)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn account_with_mailbox(dir: &std::path::Path) {
		// INBOX always exists; create a folder mailbox for the others.
		std::fs::create_dir_all(dir.join("accounts").join("alice").join("new")).expect("inbox");
	}

	#[test]
	fn owner_always_has_all_rights() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		assert_eq!(rights_of(dir.path(), "alice", "INBOX", "alice"), ALL_RIGHTS);
	}

	#[test]
	fn unknown_identifier_has_no_rights() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		assert_eq!(rights_of(dir.path(), "alice", "INBOX", "bob"), "");
	}

	#[test]
	fn set_canonicalises_and_persists() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		// Out-of-order, duplicated input is canonicalised.
		let result = set(dir.path(), "alice", "INBOX", "bob", "srl l").expect("set");
		assert_eq!(result, "lrs");
		assert_eq!(rights_of(dir.path(), "alice", "INBOX", "bob"), "lrs");
	}

	#[test]
	fn plus_and_minus_modify_existing() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		set(dir.path(), "alice", "INBOX", "bob", "lr").expect("set");
		assert_eq!(
			set(dir.path(), "alice", "INBOX", "bob", "+sw").unwrap(),
			"lrsw"
		);
		assert_eq!(
			set(dir.path(), "alice", "INBOX", "bob", "-rw").unwrap(),
			"ls"
		);
	}

	#[test]
	fn removing_all_rights_deletes_entry() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		set(dir.path(), "alice", "INBOX", "bob", "lr").expect("set");
		set(dir.path(), "alice", "INBOX", "bob", "").expect("clear");
		assert!(get(dir.path(), "alice", "INBOX").is_empty());
	}

	#[test]
	fn owner_entry_is_never_stored() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		set(dir.path(), "alice", "INBOX", "alice", "lr").expect("set");
		assert!(get(dir.path(), "alice", "INBOX").is_empty());
	}

	#[test]
	fn delete_removes_only_target() {
		let dir = tempfile::tempdir().expect("tempdir");
		account_with_mailbox(dir.path());
		set(dir.path(), "alice", "INBOX", "bob", "lr").expect("set");
		set(dir.path(), "alice", "INBOX", "carol", "lrs").expect("set");
		delete(dir.path(), "alice", "INBOX", "bob").expect("delete");
		let entries = get(dir.path(), "alice", "INBOX");
		assert_eq!(entries, vec![("carol".to_string(), "lrs".to_string())]);
	}

	#[test]
	fn valid_rights_rejects_unknown_chars() {
		assert!(valid_rights("lrswipkxtea"));
		assert!(!valid_rights("lrZ"));
	}
}
