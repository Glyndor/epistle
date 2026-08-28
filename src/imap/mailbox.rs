//! Filesystem-backed mailboxes: INBOX at `accounts/<name>/new/`, other
//! mailboxes under `accounts/<name>/folders/<mailbox>/new/`.

use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::storage::MessageCrypto;

/// A snapshot of one mailbox at SELECT time. Sequence numbers are positions
/// in `messages` (1-based); UIDs are persistent, assigned in arrival order.
#[derive(Debug)]
pub struct Snapshot {
	pub(super) account_dir: PathBuf,
	/// The account root (`<data_dir>/accounts/<name>`); used as the parent of
	/// the per-account `.archive/` directory when retention is enabled.
	pub(super) account_root: PathBuf,
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

/// Supported permanent flags (RFC 9051 section 2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Flag {
	/// `\Seen`: the message has been read.
	Seen,
	/// `\Answered`: a reply has been sent.
	Answered,
	/// `\Flagged`: marked for attention (the "star" in most clients).
	Flagged,
	/// `\Deleted`: marked for removal; expunged at CLOSE or explicit EXPUNGE.
	Deleted,
	/// `\Draft`: not yet sent.
	Draft,
}

impl Flag {
	/// Parse the IMAP flag token.
	pub fn parse(token: &str) -> Option<Flag> {
		match token.to_ascii_lowercase().as_str() {
			"\\seen" => Some(Flag::Seen),
			"\\answered" => Some(Flag::Answered),
			"\\flagged" => Some(Flag::Flagged),
			"\\deleted" => Some(Flag::Deleted),
			"\\draft" => Some(Flag::Draft),
			_ => None,
		}
	}

	/// The wire representation.
	pub fn as_str(self) -> &'static str {
		match self {
			Flag::Seen => "\\Seen",
			Flag::Answered => "\\Answered",
			Flag::Flagged => "\\Flagged",
			Flag::Deleted => "\\Deleted",
			Flag::Draft => "\\Draft",
		}
	}
}

/// Render a flag list for FETCH/STORE responses.
///
/// Builds the parenthesized list in a single pre-sized allocation, without the
/// intermediate `Vec<&str>` that `join` would require — this runs once per
/// message in every FETCH FLAGS / STORE response.
pub fn render_flags(flags: &[Flag]) -> String {
	// "(" + ")" + flag tokens + single-space separators between them.
	let capacity = 2
		+ flags.iter().map(|flag| flag.as_str().len()).sum::<usize>()
		+ flags.len().saturating_sub(1);
	let mut out = String::with_capacity(capacity);
	out.push('(');
	for (index, flag) in flags.iter().enumerate() {
		if index > 0 {
			out.push(' ');
		}
		out.push_str(flag.as_str());
	}
	out.push(')');
	out
}

/// Whether a client-supplied mailbox name is safe and supported.
pub fn valid_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= 128
		&& !name.eq_ignore_ascii_case("INBOX")
		&& name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
		&& !name.starts_with('.')
		&& !name.ends_with(' ')
}

/// The on-disk directory of a mailbox (its `new/` subdirectory).
pub fn mailbox_dir(data_dir: &Path, account: &str, mailbox: &str) -> Option<PathBuf> {
	let base = data_dir.join("accounts").join(account);
	if mailbox.eq_ignore_ascii_case("INBOX") {
		return Some(base.join("new"));
	}
	if !valid_name(mailbox) {
		return None;
	}
	Some(base.join("folders").join(mailbox).join("new"))
}

/// Whether a mailbox exists. INBOX always exists.
pub fn exists(data_dir: &Path, account: &str, mailbox: &str) -> bool {
	if mailbox.eq_ignore_ascii_case("INBOX") {
		return true;
	}
	mailbox_dir(data_dir, account, mailbox).is_some_and(|dir| dir.is_dir())
}

/// Create a mailbox. Fails if invalid or already existing.
pub fn create(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let dir = mailbox_dir(data_dir, account, mailbox)
		.filter(|_| !mailbox.eq_ignore_ascii_case("INBOX"))
		.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
	if dir.is_dir() {
		return Err(std::io::Error::other("mailbox already exists"));
	}
	std::fs::create_dir_all(&dir)
}

/// Delete a mailbox and its messages. INBOX cannot be deleted.
pub fn delete(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	if mailbox.eq_ignore_ascii_case("INBOX") || !valid_name(mailbox) {
		return Err(std::io::Error::other("cannot delete this mailbox"));
	}
	let dir = data_dir
		.join("accounts")
		.join(account)
		.join("folders")
		.join(mailbox);
	if !dir.is_dir() {
		return Err(std::io::Error::other("no such mailbox"));
	}
	std::fs::remove_dir_all(dir)
}

/// Rename a mailbox. INBOX cannot be renamed.
pub fn rename(data_dir: &Path, account: &str, from: &str, to: &str) -> std::io::Result<()> {
	if from.eq_ignore_ascii_case("INBOX")
		|| !valid_name(from)
		|| !valid_name(to)
		|| exists(data_dir, account, to)
	{
		return Err(std::io::Error::other("cannot rename"));
	}
	let folders = data_dir.join("accounts").join(account).join("folders");
	if !folders.join(from).is_dir() {
		return Err(std::io::Error::other("no such mailbox"));
	}
	std::fs::rename(folders.join(from), folders.join(to))
}

/// Existing mailbox names: INBOX plus folders, sorted.
pub fn list(data_dir: &Path, account: &str) -> Vec<String> {
	let mut names = vec!["INBOX".to_string()];
	let folders = data_dir.join("accounts").join(account).join("folders");
	if let Ok(entries) = std::fs::read_dir(folders) {
		for entry in entries.flatten() {
			if entry.path().is_dir()
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
	let account_dir = mailbox_dir(data_dir, account, mailbox)
		.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
	let tmp_dir = data_dir.join("accounts").join(account).join("tmp");
	std::fs::create_dir_all(&account_dir)?;
	std::fs::create_dir_all(&tmp_dir)?;

	let id = Uuid::now_v7();
	let tmp = tmp_dir.join(format!("{id}.eml"));
	std::fs::write(&tmp, &crypto.encode(data)?)?;
	std::fs::rename(&tmp, account_dir.join(format!("{id}.eml")))?;
	if !flags.is_empty() {
		super::flags::write_flags(&account_dir, id, flags)?;
	}
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
	let mut total = 0u64;
	for mailbox in list(data_dir, account) {
		let Some(dir) = mailbox_dir(data_dir, account, &mailbox) else {
			continue;
		};
		let Ok(entries) = std::fs::read_dir(&dir) else {
			continue;
		};
		for entry in entries.flatten() {
			if entry
				.file_name()
				.to_str()
				.is_some_and(|name| name.ends_with(".eml"))
				&& let Ok(meta) = entry.metadata()
			{
				total += crypto.stored_plaintext_len(&entry.path(), meta.len());
			}
		}
	}
	let account_root = data_dir.join("accounts").join(account);
	if let Ok(entries) = std::fs::read_dir(account_root.join(".archive")) {
		for entry in entries.flatten() {
			if entry
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
#[path = "mailbox_tests.rs"]
mod tests;
