//! Filesystem-backed mailboxes: INBOX at `accounts/<name>/new/`, other
//! mailboxes under `accounts/<name>/folders/<mailbox>/new/`.
//!
//! The mailbox snapshot, the per-mailbox CRUD and the message-counter
//! helpers live in this file. The [`Flag`] type, its serde shape and
//! the helpers that operate on flag sets live in a sibling module;
//! callers reach the type through the `crate::imap::mailbox` path
//! the rest of the crate already uses.

mod defaults;
mod flag;
pub(crate) mod journal;

pub(crate) use defaults::ensure_defaults;

pub use flag::{
	Flag, count_keywords, dedup_flags, flag_key, flag_set_contains, keywords_in, render_flags,
};

use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::imap::changelog::{Change, Op};
use crate::storage::MessageCrypto;
use crate::util::path_component::{
	AccountName, AccountRoot, FixedDir, MailboxName, MessageExt, folders_dir, message_file,
};
use crate::util::path_containment::contained_child;

/// A snapshot of one mailbox at SELECT time. Sequence numbers are positions
/// in `messages` (1-based); UIDs are persistent, assigned in arrival order.
#[derive(Debug)]
pub struct Snapshot {
	pub(super) account_dir: PathBuf,
	/// The account root (`<data_dir>/accounts/<name>`); used as the parent of
	/// the per-account `.archive/` directory when retention is enabled.
	pub(super) account_root: AccountRoot,
	/// The mailbox this snapshot was opened for, used to stamp the archive
	/// sidecar so a restored message knows where it came from.
	pub(super) mailbox: String,
	pub(super) messages: Vec<MessageRef>,
	pub(super) uid_validity: u32,
	/// Next UID to assign (one past the highest assigned), persisted.
	pub(super) uid_next: u32,
	/// Highest mod-sequence in the mailbox (CONDSTORE, RFC 7162).
	pub(super) highest_modseq: u64,
	/// At-rest crypto for decoding message bodies on read.
	pub(super) crypto: MessageCrypto,
	/// Days to keep expunged messages in `<account_root>/.archive/` before
	/// the hourly sweeper removes them. `0` keeps the legacy behaviour:
	/// expunge deletes the on-disk files immediately.
	pub(super) retention_days: u64,
	/// Unix time used as the deletion timestamp when an expunge archives a
	/// message. Sampled once at open in production; injected by [`open_at`]
	/// so tests are deterministic.
	pub(super) now: u64,
	/// Whether this snapshot came from the metadata index (fast path). Used by
	/// tests to prove the index path is exercised and skips the sidecar reads.
	#[cfg(test)]
	pub loaded_from_index: bool,
}

/// One message in the snapshot.
#[derive(Debug, Clone)]
pub struct MessageRef {
	/// Persistent UID assigned at delivery; position in the mailbox's UID
	/// space (independent of sequence numbers).
	pub uid: u32,
	pub(super) id: Uuid,
	/// RFC 5322 size of the message in octets.
	pub size: u64,
	/// Permanent flags currently set on the message.
	pub flags: Vec<Flag>,
	/// File mtime; used for INTERNALDATE.
	pub internal_date: std::time::SystemTime,
	/// Mod-sequence of the last flag change (CONDSTORE, RFC 7162).
	pub modseq: u64,
}

impl MessageRef {
	/// The message's stable UUID (its on-disk `<id>.eml` name).
	pub fn id(&self) -> Uuid {
		self.id
	}

	/// Build a [`MessageRef`] from index-decoded fields. Used by the metadata
	/// index loader, which holds the same per-message data the FS scan gathers.
	pub(super) fn from_index(
		uid: u32,
		id: Uuid,
		size: u64,
		flags: Vec<Flag>,
		internal_date: std::time::SystemTime,
		modseq: u64,
	) -> MessageRef {
		MessageRef {
			uid,
			id,
			size,
			flags,
			internal_date,
			modseq,
		}
	}
}

/// Whether a client-supplied mailbox name is a valid folder name. `INBOX` is
/// not a folder and is refused here.
pub fn valid_name(name: &str) -> bool {
	MailboxName::folder(name).is_ok()
}

/// The on-disk directory of a mailbox (its `new/` subdirectory). `None` when
/// the account or the mailbox name is not a plain path component.
pub fn mailbox_dir(data_dir: &Path, account: &str, mailbox: &str) -> Option<PathBuf> {
	let account = AccountName::new(account).ok()?;
	let mailbox = MailboxName::new(mailbox).ok()?;
	mailbox.messages_dir(&account, data_dir).ok()
}

/// Whether a mailbox exists. INBOX always exists for a valid account.
pub fn exists(data_dir: &Path, account: &str, mailbox: &str) -> bool {
	if mailbox.eq_ignore_ascii_case("INBOX") {
		return AccountName::new(account).is_ok();
	}
	mailbox_dir(data_dir, account, mailbox).is_some_and(|dir| dir.is_dir())
}

/// Create a mailbox. Fails if invalid or already existing.
pub fn create(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let account = AccountName::new(account)?;
	let dir = MailboxName::folder(mailbox)
		.map_err(|_| std::io::Error::other("invalid mailbox name"))?
		.messages_dir(&account, data_dir)?;
	if dir.is_dir() {
		return Err(std::io::Error::other("mailbox already exists"));
	}
	std::fs::create_dir_all(&dir)?;
	journal::note(data_dir, &account, &[Change::mailbox(Op::Created, mailbox)]);
	Ok(())
}

/// Delete a mailbox and its messages. INBOX cannot be deleted.
pub fn delete(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let account = AccountName::new(account)?;
	let dir = MailboxName::folder(mailbox)
		.ok()
		.and_then(|folder| folder.folder_dir(&account, data_dir).ok().flatten())
		.ok_or_else(|| std::io::Error::other("cannot delete this mailbox"))?;
	if !dir.is_dir() {
		return Err(std::io::Error::other("no such mailbox"));
	}
	// The messages go with the mailbox: each one is destroyed for JMAP.
	let ids = journal::message_ids(&contained_child(&dir, "new")?);
	std::fs::remove_dir_all(dir)?;
	let mut changes: Vec<Change> = ids
		.into_iter()
		.map(|id| Change::email(Op::Destroyed, id))
		.collect();
	changes.push(Change::mailbox(Op::Destroyed, mailbox));
	journal::note(data_dir, &account, &changes);
	Ok(())
}

/// Rename a mailbox. INBOX cannot be renamed.
pub fn rename(data_dir: &Path, account: &str, from: &str, to: &str) -> std::io::Result<()> {
	let account = AccountName::new(account)?;
	let (from_name, to_name) = (from, to);
	let (Ok(from), Ok(to)) = (MailboxName::folder(from), MailboxName::folder(to)) else {
		return Err(std::io::Error::other("cannot rename"));
	};
	let Ok(target) = to.messages_dir(&account, data_dir) else {
		return Err(std::io::Error::other("cannot rename"));
	};
	if target.is_dir() {
		return Err(std::io::Error::other("cannot rename"));
	}
	let (Ok(Some(from)), Ok(Some(to))) = (
		from.folder_dir(&account, data_dir),
		to.folder_dir(&account, data_dir),
	) else {
		return Err(std::io::Error::other("cannot rename"));
	};
	if !from.is_dir() {
		return Err(std::io::Error::other("no such mailbox"));
	}
	std::fs::rename(from, &to)?;
	// The mailbox id is its name, so the old id is gone and a new one exists;
	// every message keeps its id but its `mailboxIds` changed.
	let mut changes = vec![
		Change::mailbox(Op::Destroyed, from_name),
		Change::mailbox(Op::Created, to_name),
	];
	changes.extend(
		journal::message_ids(&contained_child(&to, "new")?)
			.into_iter()
			.map(|id| Change::email(Op::Updated, id)),
	);
	journal::note(data_dir, &account, &changes);
	Ok(())
}

/// Existing mailbox names: INBOX plus folders, sorted. An account that is not
/// a plain directory name has only INBOX.
pub fn list(data_dir: &Path, account: &str) -> Vec<String> {
	let mut names = vec!["INBOX".to_string()];
	let Ok(account) = AccountName::new(account) else {
		return names;
	};
	let entries = folders_dir(&account, data_dir).and_then(crate::util::fs_walk::read_dir);
	if let Ok(entries) = entries {
		for entry in entries.flatten() {
			if entry.file_type().is_ok_and(|kind| kind.is_dir())
				&& let Some(name) = entry.file_name().to_str()
				&& valid_name(name)
			{
				names.push(name.to_string());
			}
		}
	}
	names[1..].sort();
	names
}

/// Append a message to a mailbox crash-safely, with flags, encoding the body
/// through `crypto` at rest. Standalone because APPEND may target a mailbox that
/// is not selected.
pub fn append(
	data_dir: &Path,
	account: &str,
	mailbox: &str,
	flags: &[Flag],
	data: &[u8],
	crypto: &MessageCrypto,
) -> std::io::Result<Uuid> {
	let account = AccountName::new(account)?;
	let account_dir = MailboxName::new(mailbox)
		.map_err(|_| std::io::Error::other("invalid mailbox name"))?
		.messages_dir(&account, data_dir)?;
	let tmp_dir = account.root(data_dir)?.child(FixedDir::Tmp)?;
	let new_mailbox = !mailbox.eq_ignore_ascii_case("INBOX") && !account_dir.is_dir();
	std::fs::create_dir_all(&account_dir)?;
	std::fs::create_dir_all(&tmp_dir)?;

	let id = Uuid::now_v7();
	let tmp = message_file(&tmp_dir, id, MessageExt::Eml)?;
	std::fs::write(&tmp, &crypto.encode(data)?)?;
	std::fs::rename(&tmp, message_file(&account_dir, id, MessageExt::Eml)?)?;
	if !flags.is_empty() {
		super::flags::write_flags(&account_dir, id, flags)?;
	}
	let mut changes = Vec::with_capacity(3);
	if new_mailbox {
		changes.push(Change::mailbox(Op::Created, mailbox));
	}
	changes.push(Change::email(Op::Created, id));
	changes.push(Change::mailbox(Op::Updated, mailbox));
	journal::note(data_dir, &account, &changes);
	Ok(id)
}

/// The `(UIDVALIDITY, UID)` assigned to an appended message, for the UIDPLUS
/// `APPENDUID` response. `None` if the mailbox can no longer be opened or the
/// message has already vanished.
pub fn appenduid(data_dir: &Path, account: &str, mailbox: &str, id: Uuid) -> Option<(u32, u32)> {
	// Only UIDs are read here, never a message body, so no key is needed.
	let snapshot = Snapshot::open(data_dir, account, mailbox, &MessageCrypto::disabled()).ok()?;
	let uid = snapshot.messages().find(|message| message.id == id)?.uid;
	Some((snapshot.uid_validity(), uid))
}

/// Total bytes stored for an account: the sum of every message's plaintext size
/// across INBOX, every folder, and the per-account archive (RFC 9208 STORAGE
/// usage). Counts the message size a client sees, so quota is unaffected by
/// whether the store is encrypted. Archived messages count toward the quota:
/// they are still messages stored on behalf of the account.
pub fn account_usage(data_dir: &Path, account: &str, crypto: &MessageCrypto) -> u64 {
	let Ok(account_name) = AccountName::new(account) else {
		return 0;
	};
	let _warnings = crate::util::fs_walk::warning_scope();
	let mut total = 0u64;
	for mailbox in list(data_dir, account) {
		let Some(dir) = mailbox_dir(data_dir, account, &mailbox) else {
			continue;
		};
		let Ok(entries) = crate::util::fs_walk::read_dir(&dir) else {
			continue;
		};
		for entry in entries.flatten() {
			if entry.file_type().is_ok_and(|kind| kind.is_file())
				&& entry
					.file_name()
					.to_str()
					.is_some_and(|name| name.ends_with(".eml"))
				&& let Ok(meta) = entry.metadata()
			{
				total += crypto.stored_plaintext_len(&entry.path(), meta.len());
			}
		}
	}
	let archive = account_name
		.root(data_dir)
		.and_then(|root| root.child(FixedDir::Archive));
	if let Ok(entries) = archive.and_then(crate::util::fs_walk::read_dir) {
		for entry in entries.flatten() {
			if entry.file_type().is_ok_and(|kind| kind.is_file())
				&& entry
					.file_name()
					.to_str()
					.is_some_and(|name| name.ends_with(".eml"))
				&& let Ok(meta) = entry.metadata()
			{
				total += crypto.stored_plaintext_len(&entry.path(), meta.len());
			}
		}
	}
	total
}

/// Subscribe to a mailbox (the mailbox must already exist).
pub fn subscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	super::subscriptions::subscribe(data_dir, account, mailbox)
}
/// Remove a subscription. Silently succeeds if not subscribed.
pub fn unsubscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	super::subscriptions::unsubscribe(data_dir, account, mailbox)
}

/// Subscribed mailboxes; INBOX is always subscribed.
pub fn list_subscribed(data_dir: &Path, account: &str) -> Vec<String> {
	super::subscriptions::list_subscribed(data_dir, account)
}

#[cfg(test)]
#[path = "../mailbox_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../mailbox_tests_path.rs"]
mod tests_path;

#[cfg(test)]
#[path = "../mailbox_tests_remove.rs"]
mod tests_remove;
