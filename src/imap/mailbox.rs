//! Filesystem-backed mailboxes: INBOX at `accounts/<name>/new/`, other
//! mailboxes under `accounts/<name>/folders/<mailbox>/new/`.

use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::storage::MessageCrypto;

/// A snapshot of one mailbox at SELECT time. Sequence numbers are positions
/// in `messages` (1-based); UIDs are persistent, assigned in arrival order.
#[derive(Debug)]
pub struct Snapshot {
	account_dir: PathBuf,
	messages: Vec<MessageRef>,
	uid_validity: u32,
	/// Next UID to assign (one past the highest assigned), persisted.
	uid_next: u32,
	/// Highest mod-sequence in the mailbox (CONDSTORE, RFC 7162).
	highest_modseq: u64,
	/// At-rest crypto for decoding message bodies on read.
	crypto: MessageCrypto,
}

/// One message in the snapshot.
#[derive(Debug, Clone)]
pub struct MessageRef {
	pub uid: u32,
	id: Uuid,
	pub size: u64,
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
}

/// Supported permanent flags (RFC 9051 section 2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Flag {
	Seen,
	Answered,
	Flagged,
	Deleted,
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

impl Snapshot {
	/// Build the snapshot of any existing mailbox, decoding message bodies
	/// through `crypto` on read. Use [`MessageCrypto::disabled`] for a plaintext
	/// store.
	pub fn open(
		data_dir: &Path,
		account: &str,
		mailbox: &str,
		crypto: &MessageCrypto,
	) -> std::io::Result<Snapshot> {
		let account_dir = mailbox_dir(data_dir, account, mailbox)
			.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
		let mut ids: Vec<Uuid> = Vec::new();
		match std::fs::read_dir(&account_dir) {
			Ok(entries) => {
				for entry in entries {
					let entry = entry?;
					let name = entry.file_name();
					let Some(name) = name.to_str() else { continue };
					if let Some(stem) = name.strip_suffix(".eml")
						&& let Ok(id) = Uuid::parse_str(stem)
					{
						ids.push(id);
					}
				}
			}
			// An account that never received mail has no directory yet.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
		ids.sort();

		let initial_counter = super::uid::read_counter(&account_dir);
		let mut uid_counter = initial_counter;
		let mut messages = Vec::with_capacity(ids.len());
		for id in ids.iter() {
			let path = account_dir.join(format!("{id}.eml"));
			let meta = std::fs::metadata(&path);
			// RFC822.SIZE must be the plaintext size a client sees, not the
			// on-disk envelope size, so subtract the fixed crypto overhead for an
			// encrypted file.
			let size = meta
				.as_ref()
				.map(|m| crypto.stored_plaintext_len(&path, m.len()))
				.unwrap_or(0);
			let internal_date = meta
				.as_ref()
				.ok()
				.and_then(|m| m.modified().ok())
				.unwrap_or(std::time::SystemTime::UNIX_EPOCH);
			messages.push(MessageRef {
				uid: super::uid::assign_or_read(&account_dir, *id, &mut uid_counter),
				id: *id,
				size,
				flags: read_flags(&account_dir, *id),
				internal_date,
				modseq: super::modseq::read_message(&account_dir, *id),
			});
		}
		if uid_counter > initial_counter {
			let _ = super::uid::write_counter(&account_dir, uid_counter);
		}
		// HIGHESTMODSEQ is the persisted counter, never below any message's.
		let highest_modseq = super::modseq::read_counter(&account_dir)
			.max(messages.iter().map(|m| m.modseq).max().unwrap_or(1))
			.max(1);
		let uid_validity = super::uidvalidity::read_or_init(&account_dir);
		Ok(Snapshot {
			account_dir,
			messages,
			uid_validity,
			uid_next: uid_counter + 1,
			highest_modseq,
			crypto: crypto.clone(),
		})
	}

	/// The mailbox's highest mod-sequence (CONDSTORE).
	pub fn highest_modseq(&self) -> u64 {
		self.highest_modseq
	}

	/// UIDs expunged after `modseq` (QRESYNC `VANISHED (EARLIER)`, RFC 7162).
	pub fn vanished_since(&self, modseq: u64) -> Vec<u32> {
		super::vanished::since(&self.account_dir, modseq)
	}

	pub fn len(&self) -> usize {
		self.messages.len()
	}

	pub fn is_empty(&self) -> bool {
		self.messages.is_empty()
	}

	pub fn uid_validity(&self) -> u32 {
		self.uid_validity
	}

	/// Iterator over all messages in sequence order.
	pub fn messages(&self) -> impl Iterator<Item = &MessageRef> {
		self.messages.iter()
	}

	/// Next UID a new message would get (the persisted counter, never reused).
	pub fn uid_next(&self) -> u32 {
		self.uid_next
	}

	/// Message by 1-based sequence number.
	pub fn by_sequence(&self, sequence: u32) -> Option<&MessageRef> {
		self.messages
			.get(usize::try_from(sequence).ok()?.checked_sub(1)?)
	}

	/// Sequence number for a UID.
	pub fn sequence_of_uid(&self, uid: u32) -> Option<u32> {
		self.messages
			.iter()
			.position(|message| message.uid == uid)
			.map(|index| u32::try_from(index + 1).unwrap_or(u32::MAX))
	}

	/// Raw (plaintext) message bytes, decoding the at-rest envelope when the file
	/// is encrypted. Fails closed on a decryption error rather than returning
	/// ciphertext.
	pub fn read(&self, message: &MessageRef) -> std::io::Result<Vec<u8>> {
		let stored = std::fs::read(self.account_dir.join(format!("{}.eml", message.id)))?;
		self.crypto.decode(&stored)
	}

	/// Replace the flags of the message at `sequence` (1-based), persisting
	/// crash-safely. Returns the new flag set.
	pub fn store_flags(&mut self, sequence: u32, flags: Vec<Flag>) -> std::io::Result<&[Flag]> {
		let index = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
			.ok_or_else(|| std::io::Error::other("no such message"))?;
		// A STORE that does not change the flag set must not touch the disk or
		// advance the mod-sequence (RFC 7162: only an actual change bumps MODSEQ).
		// Skipping the sidecar rewrite + two counter writes removes the
		// write-amplification of the common "re-mark \Seen" pattern.
		if flags_equal(&self.messages[index].flags, &flags) {
			return Ok(&self.messages[index].flags);
		}
		let id = self.messages[index].id;
		write_flags(&self.account_dir, id, &flags)?;
		// A flag change advances the mailbox mod-sequence and stamps the message.
		let modseq = super::modseq::next_counter(&self.account_dir)?;
		let _ = super::modseq::write_message(&self.account_dir, id, modseq);
		self.highest_modseq = self.highest_modseq.max(modseq);
		self.messages[index].flags = flags;
		self.messages[index].modseq = modseq;
		Ok(&self.messages[index].flags)
	}

	/// Remove one message (file + sidecar) by sequence number.
	pub fn remove_at(&mut self, sequence: u32) -> std::io::Result<()> {
		let index = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
			.ok_or_else(|| std::io::Error::other("no such message"))?;
		let uid = self.messages[index].uid;
		self.remove_files(self.messages[index].id);
		self.messages.remove(index);
		super::vanished::record_advancing(&self.account_dir, &[uid]);
		Ok(())
	}

	/// Remove every `\Deleted` message. Returns the expunged sequence numbers
	/// in emission order (each valid at the moment it is sent).
	pub fn expunge(&mut self) -> std::io::Result<Vec<u32>> {
		self.expunge_where(|_| true)
	}

	/// Expunge only `\Deleted` messages whose UID is in `uids` (UID EXPUNGE,
	/// RFC 4315).
	pub fn expunge_uids(&mut self, uids: &[u32]) -> std::io::Result<Vec<u32>> {
		self.expunge_where(|uid| uids.contains(&uid))
	}

	/// Expunge every `\Deleted` message whose UID passes `keep`, logging the
	/// vanished UIDs for QRESYNC.
	fn expunge_where(&mut self, keep: impl Fn(u32) -> bool) -> std::io::Result<Vec<u32>> {
		let mut expunged = Vec::new();
		let mut vanished = Vec::new();
		let mut index = 0;
		while index < self.messages.len() {
			let message = &self.messages[index];
			if message.flags.contains(&Flag::Deleted) && keep(message.uid) {
				vanished.push(message.uid);
				self.remove_files(message.id);
				self.messages.remove(index);
				expunged.push(u32::try_from(index + 1).unwrap_or(u32::MAX));
			} else {
				index += 1;
			}
		}
		super::vanished::record_advancing(&self.account_dir, &vanished);
		Ok(expunged)
	}

	/// Remove a message's `.eml` and its `.flags`/`.uid` sidecars.
	fn remove_files(&self, id: Uuid) {
		let _ = std::fs::remove_file(self.account_dir.join(format!("{id}.eml")));
		let _ = std::fs::remove_file(self.account_dir.join(format!("{id}.flags")));
		let _ = std::fs::remove_file(self.account_dir.join(format!("{id}.uid")));
	}
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
		write_flags(&account_dir, id, flags)?;
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
/// across INBOX and all folders (RFC 9208 STORAGE usage). Counts the message
/// size a client sees, so quota is unaffected by whether the store is encrypted.
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
	total
}

/// Subscribe to a mailbox (the mailbox must already exist).
pub fn subscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	if !exists(data_dir, account, mailbox) {
		return Err(std::io::Error::other("no such mailbox"));
	}
	let normalized = if mailbox.eq_ignore_ascii_case("INBOX") {
		"INBOX".to_string()
	} else {
		mailbox.to_string()
	};
	let mut subs = list_subscribed(data_dir, account);
	if !subs.iter().any(|s| s.eq_ignore_ascii_case(&normalized)) {
		subs.push(normalized);
		write_subscriptions(data_dir, account, &subs)?;
	}
	Ok(())
}

/// Remove a subscription. Silently succeeds if not subscribed.
pub fn unsubscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let subs: Vec<String> = list_subscribed(data_dir, account)
		.into_iter()
		.filter(|s| !s.eq_ignore_ascii_case(mailbox))
		.collect();
	write_subscriptions(data_dir, account, &subs)
}

/// Subscribed mailboxes; INBOX is always subscribed.
pub fn list_subscribed(data_dir: &Path, account: &str) -> Vec<String> {
	let path = data_dir
		.join("accounts")
		.join(account)
		.join(".subscriptions");
	let mut names: Vec<String> = std::fs::read_to_string(&path)
		.unwrap_or_default()
		.lines()
		.filter(|l| !l.is_empty())
		.map(str::to_string)
		.collect();
	if !names.iter().any(|n| n.eq_ignore_ascii_case("INBOX")) {
		names.insert(0, "INBOX".to_string());
	}
	names
}

fn write_subscriptions(data_dir: &Path, account: &str, names: &[String]) -> std::io::Result<()> {
	let path = data_dir
		.join("accounts")
		.join(account)
		.join(".subscriptions");
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	std::fs::write(
		&path,
		names.iter().fold(String::new(), |mut s, n| {
			s.push_str(n);
			s.push('\n');
			s
		}),
	)
}

/// Whether two flag lists denote the same flag set, independent of order or
/// duplicates. Used to detect a no-op STORE and avoid a redundant disk write.
fn flags_equal(current: &[Flag], next: &[Flag]) -> bool {
	current.iter().all(|flag| next.contains(flag)) && next.iter().all(|flag| current.contains(flag))
}

fn read_flags(account_dir: &Path, id: Uuid) -> Vec<Flag> {
	std::fs::read(account_dir.join(format!("{id}.flags")))
		.ok()
		.and_then(|bytes| serde_json::from_slice(&bytes).ok())
		.unwrap_or_default()
}

fn write_flags(account_dir: &Path, id: Uuid, flags: &[Flag]) -> std::io::Result<()> {
	let bytes = serde_json::to_vec(flags).map_err(std::io::Error::other)?;
	let tmp = account_dir.join(format!("{id}.flags.tmp"));
	std::fs::write(&tmp, &bytes)?;
	std::fs::rename(&tmp, account_dir.join(format!("{id}.flags")))
}

#[cfg(test)]
#[path = "mailbox_tests.rs"]
mod tests;
