//! Crash-safe filesystem spool for accepted messages.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::crypto::MessageCrypto;

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

impl FsSpool {
	/// Open (creating if needed) the spool under `data_dir`, with no at-rest
	/// encryption. The encrypting variant is [`FsSpool::open_with_crypto`].
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		Self::open_with_crypto(data_dir, MessageCrypto::disabled())
	}

	/// Open the spool under `data_dir`, encrypting/decrypting the raw message
	/// (`.eml`) files through `crypto`. Envelope JSON sidecars are unaffected.
	pub fn open_with_crypto(data_dir: &Path, crypto: MessageCrypto) -> std::io::Result<Self> {
		let root = data_dir.join("spool");
		fs::create_dir_all(root.join("tmp"))?;
		fs::create_dir_all(root.join("new"))?;
		Ok(FsSpool { root, crypto })
	}

	/// Persist one message crash-safely and return its spool id.
	///
	/// Both files are first written and fsynced under `tmp/`, then renamed
	/// into `new/` — envelope last, so a visible envelope guarantees a
	/// complete message file next to it.
	pub fn store(&self, message: &AcceptedMessage) -> std::io::Result<Uuid> {
		let id = Uuid::now_v7();
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
		};

		let tmp_message = self.root.join("tmp").join(format!("{id}.eml"));
		let tmp_envelope = self.root.join("tmp").join(format!("{id}.json"));
		let final_message = self.root.join("new").join(format!("{id}.eml"));
		let final_envelope = self.root.join("new").join(format!("{id}.json"));

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
			crate::util::fs_walk::read(self.root.join("new").join(format!("{id}.json")))?;
		let envelope: Envelope =
			serde_json::from_slice(&envelope_bytes).map_err(std::io::Error::other)?;
		let data = self.crypto.decode(&crate::util::fs_walk::read(
			self.root.join("new").join(format!("{id}.eml")),
		)?)?;
		Ok(SpoolEntry { envelope, data })
	}

	/// List ids of all complete spooled messages, oldest first.
	pub fn list(&self) -> std::io::Result<Vec<Uuid>> {
		let mut ids = Vec::new();
		for entry in crate::util::fs_walk::read_dir(self.root.join("new"))? {
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
		let bytes = crate::util::fs_walk::read(self.root.join("new").join(format!("{id}.json")))?;
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
		let tmp = self
			.root
			.join("tmp")
			.join(format!("{id}.{}.json", Uuid::now_v7()));
		let bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		let written = write_sync(&tmp, &bytes)
			.and_then(|()| fs::rename(&tmp, self.root.join("new").join(format!("{id}.json"))));
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
			.open(self.root.join("lock"))?;
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
		fs::remove_file(self.root.join("new").join(format!("{id}.json")))?;
		fs::remove_file(self.root.join("new").join(format!("{id}.eml")))?;
		Ok(())
	}
}

impl MessageSink for FsSpool {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.store(&message)
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

		let id = spool.store(&sample_message()).expect("store");
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
		let id = spool.store(&message).expect("store");
		assert!(spool.load(id).expect("load").envelope.require_tls);
	}

	#[test]
	fn list_returns_ids_oldest_first() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let first = spool.store(&sample_message()).expect("store first");
		let second = spool.store(&sample_message()).expect("store second");

		assert_eq!(spool.list().expect("list"), vec![first, second]);
	}

	#[test]
	fn remove_deletes_both_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let id = spool.store(&sample_message()).expect("store");
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
