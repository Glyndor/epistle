//! Crash-safe filesystem spool for accepted messages.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};
use crate::util::path_component::{MessageExt, message_file};
use crate::util::path_containment::contained;

use super::crypto::MessageCrypto;
pub use super::spool_recipients::{RecipientState, RecipientStatus};

/// Envelope metadata stored next to the raw message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
	/// Spool id (UUID v7: time-ordered).
	pub id: Uuid,
	/// SMTP reverse-path (empty for bounces).
	pub reverse_path: String,
	/// Accepted recipients.
	pub recipients: Vec<String>,
	/// Failed delivery attempts so far.
	#[serde(default)]
	pub attempts: u32,
	/// Epoch seconds before which delivery must not be retried.
	#[serde(default)]
	pub next_attempt: u64,
	/// REQUIRETLS (RFC 8689): onward delivery must use verified TLS.
	#[serde(default)]
	pub require_tls: bool,
	/// Recipients that suppress failure DSNs (`NOTIFY=NEVER`, RFC 3461).
	#[serde(default)]
	pub no_dsn: Vec<String>,
	/// Whether the "delivery delayed" warning DSN has already been sent, so it
	/// is sent at most once (RFC 5321 §4.5.4.1).
	#[serde(default)]
	pub delay_warned: bool,
	/// Epoch seconds at which an operator put the entry on hold. A held entry
	/// is never attempted until released. `None` for an entry in the normal
	/// flow, which is also how every spool file written before this field
	/// existed loads.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub held: Option<u64>,
	/// Seconds the entry has spent on hold in earlier hold/release cycles. The
	/// give-up window counts message age minus this, so a message an operator
	/// parked for a week is not bounced on its first attempt after release.
	#[serde(default, skip_serializing_if = "is_zero")]
	pub held_secs: u64,
	/// Reason the most recent delivery attempt failed, for `queue show`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_error: Option<String>,
	/// Delivery state per recipient (see [`RecipientState`]). Empty in every
	/// envelope written before it existed, which reads as all pending.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub recipient_state: BTreeMap<String, RecipientState>,
	/// The local account that submitted the message, when the submission went
	/// through one of this server's submission paths (SMTP after AUTH, the
	/// API, JMAP). `None` when the sender is an external relay or the entry
	/// was written before this field existed, which the delivery log records
	/// as "submitted by an unknown account".
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub account: Option<String>,
	/// The caller-supplied correlation map the API allows on a `send`. Kept
	/// alongside the message in the envelope so the delivery log and the
	/// delivery webhooks can copy it onto every record they emit, but never
	/// written into the message itself (the field is a server-side tag, not
	/// a header). Empty in every envelope written before this field existed.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub extra: BTreeMap<String, String>,
}

fn is_zero(value: &u64) -> bool {
	*value == 0
}

/// Longest `last_error` kept in the envelope: remote replies can be long and
/// the field is for an operator's eyes only.
const LAST_ERROR_MAX: usize = 512;

impl Envelope {
	/// Put the entry on hold as of `now`. Holding an entry that is already
	/// held keeps the original start so the held time is not shortened.
	pub fn hold(&mut self, now: u64) {
		if self.held.is_none() {
			self.held = Some(now);
		}
	}

	/// Release a held entry as of `now`, folding the time spent on hold into
	/// [`Envelope::held_secs`]. A no-op for an entry that is not held.
	pub fn release(&mut self, now: u64) {
		if let Some(since) = self.held.take() {
			self.held_secs = self.held_secs.saturating_add(now.saturating_sub(since));
		}
	}
}

/// One spooled message: envelope plus raw message bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolEntry {
	/// Envelope metadata (sender, recipients, retry state).
	pub envelope: Envelope,
	/// Raw RFC 5322 message bytes, exactly as accepted.
	pub data: Vec<u8>,
}

/// Filesystem spool rooted at `<data_dir>/spool`.
#[derive(Debug)]
pub struct FsSpool {
	root: PathBuf,
	crypto: MessageCrypto,
}

/// The two directories of the spool: `tmp/` while a write is in flight, `new/`
/// once the entry is complete.
#[derive(Debug, Clone, Copy)]
enum SpoolDir {
	Tmp,
	New,
}

impl SpoolDir {
	fn name(self) -> &'static str {
		match self {
			Self::Tmp => "tmp",
			Self::New => "new",
		}
	}
}

impl FsSpool {
	/// The path of one spooled file. The id is a [`Uuid`] and the extension a
	/// closed set, so nothing but a plain file name is ever joined onto the root.
	fn entry_file(&self, dir: SpoolDir, id: Uuid, ext: MessageExt) -> std::io::Result<PathBuf> {
		message_file(&self.path_in(Path::new(dir.name()))?, id, ext)
	}

	/// `relative` under the spool root, resolved and checked to stay inside it.
	fn path_in(&self, relative: &Path) -> std::io::Result<PathBuf> {
		contained(&self.root, &self.root.join(relative))
	}

	/// Open (creating if needed) the spool under `data_dir`, with no at-rest
	/// encryption. The encrypting variant is [`FsSpool::open_with_crypto`].
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		Self::open_with_crypto(data_dir, MessageCrypto::disabled())
	}

	/// The at-rest crypto this spool uses for stored message bodies.
	/// The save-sent helper borrows this so the Sent copy is encoded
	/// the same way the rest of the account's mail is.
	pub fn crypto(&self) -> &MessageCrypto {
		&self.crypto
	}

	/// The directory this spool lives under. The save-sent helper
	/// writes the copy under `<data_dir>/accounts/<name>/folders/Sent`
	/// so the helper needs the data dir root.
	pub fn data_dir(&self) -> &Path {
		self.root.parent().expect("spool root is under data_dir")
	}

	/// Open the spool under `data_dir`, encrypting/decrypting the raw message
	/// (`.eml`) files through `crypto`. Envelope JSON sidecars are unaffected.
	pub fn open_with_crypto(data_dir: &Path, crypto: MessageCrypto) -> std::io::Result<Self> {
		let root = contained(data_dir, &data_dir.join("spool"))?;
		let spool = FsSpool { root, crypto };
		fs::create_dir_all(spool.path_in(Path::new(SpoolDir::Tmp.name()))?)?;
		fs::create_dir_all(spool.path_in(Path::new(SpoolDir::New.name()))?)?;
		Ok(spool)
	}

	/// Persist one message crash-safely and return its spool id.
	///
	/// Both files are first written and fsynced under `tmp/`, then renamed
	/// into `new/` — envelope last, so a visible envelope guarantees a
	/// complete message file next to it. `account` is the local account that
	/// submitted the message (used by the delivery log); pass `None` for the
	/// SMTP relay hop that has none. The caller-supplied `extra` correlation
	/// map is the `extra` object the API path may attach to a submission;
	/// the delivery log and webhooks copy it onto every record they emit,
	/// but it is never written into the message itself.
	pub fn store(
		&self,
		message: &AcceptedMessage,
		account: Option<&str>,
		extra: &BTreeMap<String, String>,
	) -> std::io::Result<Uuid> {
		self.store_as(message, Uuid::now_v7(), account, extra)
	}

	/// [`FsSpool::store`] under an id the caller chose, so a submission can
	/// name its queue entry before it is routed. The id must be fresh (a
	/// UUID v7 minted for this message); it is returned unchanged.
	pub fn store_as(
		&self,
		message: &AcceptedMessage,
		id: Uuid,
		account: Option<&str>,
		extra: &BTreeMap<String, String>,
	) -> std::io::Result<Uuid> {
		let account = account
			.filter(|value| !value.is_empty())
			.map(str::to_string);
		let envelope = Envelope {
			id,
			reverse_path: message.reverse_path.clone(),
			recipients: message.recipients.clone(),
			attempts: 0,
			next_attempt: 0,
			require_tls: message.require_tls,
			no_dsn: message.no_dsn.clone(),
			delay_warned: false,
			held: None,
			held_secs: 0,
			last_error: None,
			recipient_state: BTreeMap::new(),
			account,
			extra: extra.clone(),
		};

		let tmp_message = self.entry_file(SpoolDir::Tmp, id, MessageExt::Eml)?;
		let tmp_envelope = self.entry_file(SpoolDir::Tmp, id, MessageExt::Json)?;
		let final_message = self.entry_file(SpoolDir::New, id, MessageExt::Eml)?;
		let final_envelope = self.entry_file(SpoolDir::New, id, MessageExt::Json)?;

		write_sync(&tmp_message, &self.crypto.encode(&message.data)?)?;
		let envelope_bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		write_sync(&tmp_envelope, &envelope_bytes)?;

		fs::rename(&tmp_message, &final_message)?;
		fs::rename(&tmp_envelope, &final_envelope)?;
		Ok(id)
	}

	/// Load one spooled entry by id.
	pub fn load(&self, id: Uuid) -> std::io::Result<SpoolEntry> {
		let envelope_bytes =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		let envelope: Envelope =
			serde_json::from_slice(&envelope_bytes).map_err(std::io::Error::other)?;
		let body = self.entry_file(SpoolDir::New, id, MessageExt::Eml)?;
		let data = self.crypto.decode(&crate::util::fs_walk::read(body)?)?;
		Ok(SpoolEntry { envelope, data })
	}

	/// List ids of all complete spooled messages, oldest first.
	pub fn list(&self) -> std::io::Result<Vec<Uuid>> {
		let mut ids = Vec::new();
		for entry in crate::util::fs_walk::read_dir(self.path_in(Path::new(SpoolDir::New.name()))?)?
		{
			let entry = entry?;
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
			let name = entry.file_name();
			let Some(name) = name.to_str() else {
				continue;
			};
			if let Some(stem) = name.strip_suffix(".json")
				&& let Ok(id) = Uuid::parse_str(stem)
			{
				ids.push(id);
			}
		}
		// UUID v7 sorts chronologically.
		ids.sort();
		Ok(ids)
	}

	/// Load only the envelope of an entry, never the message body. This is
	/// what `queue show` uses, so an operator command cannot print mail.
	pub fn load_envelope(&self, id: Uuid) -> std::io::Result<Envelope> {
		let bytes =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		serde_json::from_slice(&bytes).map_err(std::io::Error::other)
	}

	/// Read-modify-write one envelope under the spool lock and return the
	/// stored result.
	///
	/// The delivery worker and the operator CLI are separate processes editing
	/// the same files. Every edit and every removal takes an exclusive `flock`
	/// on `<root>/lock`, so two edits cannot interleave their load and write
	/// (a lost update), and an edit cannot resurrect an envelope a removal just
	/// deleted. The new envelope goes to a uniquely named file under `tmp/` and
	/// is renamed over the old one, so a reader never sees a partial file. A
	/// missing entry is reported as `NotFound` and nothing is written.
	pub fn update_envelope(
		&self,
		id: Uuid,
		edit: impl FnOnce(&mut Envelope),
	) -> std::io::Result<Envelope> {
		let _guard = self.lock()?;
		let mut envelope = self.load_envelope(id)?;
		edit(&mut envelope);
		let tmp = self.path_in(
			&Path::new(SpoolDir::Tmp.name()).join(format!("{id}.{}.json", Uuid::now_v7())),
		)?;
		let bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		let written = write_sync(&tmp, &bytes)
			.and_then(|()| fs::rename(&tmp, self.entry_file(SpoolDir::New, id, MessageExt::Json)?));
		if let Err(error) = written {
			let _ = fs::remove_file(&tmp);
			return Err(error);
		}
		Ok(envelope)
	}

	/// Take the exclusive spool lock; it is released when the guard drops.
	fn lock(&self) -> std::io::Result<fs::File> {
		let file = fs::OpenOptions::new()
			.create(true)
			.truncate(false)
			.write(true)
			.open(self.path_in(Path::new("lock"))?)?;
		file.lock()?;
		Ok(file)
	}

	/// Record a failed delivery attempt crash-safely, returning the new
	/// attempt count. `next_attempt` is when the next retry is allowed and
	/// `reason` is kept (truncated) as the entry's last error.
	pub fn record_attempt(
		&self,
		id: Uuid,
		next_attempt: u64,
		reason: &str,
	) -> std::io::Result<u32> {
		let envelope = self.update_envelope(id, |envelope| {
			envelope.attempts += 1;
			envelope.next_attempt = next_attempt;
			envelope.last_error = Some(reason.chars().take(LAST_ERROR_MAX).collect());
		})?;
		Ok(envelope.attempts)
	}

	/// Mark the delay-warning DSN as sent, crash-safely, so it is sent once.
	pub fn mark_delay_warned(&self, id: Uuid) -> std::io::Result<()> {
		self.update_envelope(id, |envelope| envelope.delay_warned = true)
			.map(|_| ())
	}

	/// Remove a spooled message after successful processing.
	pub fn remove(&self, id: Uuid) -> std::io::Result<()> {
		let _guard = self.lock()?;
		// Envelope first: a message file without an envelope is invisible.
		fs::remove_file(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		fs::remove_file(self.entry_file(SpoolDir::New, id, MessageExt::Eml)?)?;
		Ok(())
	}
}

impl MessageSink for FsSpool {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.submit(message, Uuid::now_v7(), "", &BTreeMap::new())
	}

	fn submit(
		&self,
		message: AcceptedMessage,
		queue_id: Uuid,
		account: &str,
		extra: &BTreeMap<String, String>,
	) -> Result<(), SinkError> {
		self.store_as(&message, queue_id, Some(account), extra)
			.map(|_| ())
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}
}

/// Write `bytes` to `path` and fsync the file before returning.
pub(super) fn write_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	let mut file = fs::File::create(path)?;
	file.write_all(bytes)?;
	file.sync_all()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_message() -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "alice@example.org".into(),
			recipients: vec!["bob@example.org".into()],
			data: b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		}
	}

	#[test]
	fn stores_and_loads_roundtrip() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let id = spool
			.store(&sample_message(), None, &BTreeMap::new())
			.expect("store");
		let entry = spool.load(id).expect("load");

		assert_eq!(entry.envelope.id, id);
		assert_eq!(entry.envelope.reverse_path, "alice@example.org");
		assert_eq!(
			entry.envelope.recipients,
			vec!["bob@example.org".to_string()]
		);
		assert_eq!(entry.data, sample_message().data);
	}

	#[test]
	fn store_preserves_require_tls() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		let mut message = sample_message();
		message.require_tls = true;
		let id = spool
			.store(&message, None, &BTreeMap::new())
			.expect("store");
		assert!(spool.load(id).expect("load").envelope.require_tls);
	}

	#[test]
	fn list_returns_ids_oldest_first() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let first = spool
			.store(&sample_message(), None, &BTreeMap::new())
			.expect("store first");
		let second = spool
			.store(&sample_message(), None, &BTreeMap::new())
			.expect("store second");

		assert_eq!(spool.list().expect("list"), vec![first, second]);
	}

	#[test]
	fn remove_deletes_both_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let id = spool
			.store(&sample_message(), None, &BTreeMap::new())
			.expect("store");
		spool.remove(id).expect("remove");

		assert!(spool.list().expect("list").is_empty());
		assert!(spool.load(id).is_err());
	}

	#[test]
	fn load_unknown_id_fails() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		assert!(spool.load(Uuid::now_v7()).is_err());
	}

	#[test]
	fn list_ignores_foreign_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		fs::write(dir.path().join("spool/new/readme.txt"), b"not mail").expect("write");
		fs::write(dir.path().join("spool/new/bad.json"), b"{}").expect("write");
		assert!(spool.list().expect("list").is_empty());
	}

	#[test]
	fn incomplete_tmp_files_are_invisible() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		// Simulate a crash: files in tmp/ never renamed.
		fs::write(dir.path().join("spool/tmp/crash.eml"), b"partial").expect("write");
		assert!(spool.list().expect("list").is_empty());
	}

	#[test]
	fn sink_implementation_stores_messages() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		spool.deliver(sample_message()).expect("deliver");
		assert_eq!(spool.list().expect("list").len(), 1);
	}

	#[test]
	fn open_fails_on_unwritable_root() {
		let result = FsSpool::open(Path::new("/proc/no-such-dir"));
		assert!(result.is_err());
	}
}

#[cfg(test)]
#[path = "spool_tests_edit.rs"]
mod tests_edit;
