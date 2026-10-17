//! Crash-safe filesystem spool for accepted messages.

use std::fs;
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError, Submission};
use crate::util::path_component::{MessageExt, message_file};
use crate::util::path_containment::contained;

use super::crypto::MessageCrypto;
pub(super) use super::spool_permissions::write_sync;
use super::spool_permissions::{
	FILE_MODE, audit_permissions, count_loose_permissions, create_spool_dir,
};
pub use super::spool_recipients::{RecipientState, RecipientStatus};
#[path = "spool_envelope.rs"]
mod envelope;
use envelope::LAST_ERROR_MAX;
pub use envelope::{Envelope, PendingOutcome};

/// Writes the evidence acceptance record for the bytes about to be queued.
pub type EvidenceHook<'a> = &'a dyn Fn(&[u8]) -> std::io::Result<()>;

/// How [`FsSpool::store_with`] stores one message.
pub struct StoreOptions<'a> {
	/// The submitting account, `None` for relayed mail.
	pub account: Option<&'a str>,
	/// The caller-supplied correlation map.
	pub extra: &'a BTreeMap<String, String>,
	/// The class the server granted.
	pub class: crate::evidence::MailClass,
	/// Writes the evidence acceptance record for the queued bytes; `None`
	/// when no evidence is kept for this message.
	pub evidence: Option<EvidenceHook<'a>>,
	/// Days the acceptance is kept, which its outcomes inherit; `0` when no
	/// evidence is kept.
	pub retain_days: u32,
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

/// How an envelope file was stored on disk: sealed under the AEAD with the
/// message id as AAD, or the legacy plaintext written before at-rest
/// encryption covered envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodedEnvelope {
	Sealed,
	Plaintext,
}

impl FsSpool {
	/// The path of one spooled file. The id is a [`Uuid`] and the extension a
	/// closed set, so nothing but a plain file name is ever joined onto the root.
	fn entry_file(&self, dir: SpoolDir, id: Uuid, ext: MessageExt) -> std::io::Result<PathBuf> {
		message_file(&self.path_in(Path::new(dir.name()))?, id, ext)
	}

	/// `relative` under the spool root, resolved and checked to stay inside it.
	pub(super) fn path_in(&self, relative: &Path) -> std::io::Result<PathBuf> {
		contained(&self.root, &self.root.join(relative))
	}

	/// Open (creating if needed) the spool under `data_dir`, with no at-rest
	/// encryption. The encrypting variant is [`FsSpool::open_with_crypto`].
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		Self::open_with_crypto(data_dir, MessageCrypto::disabled())
	}

	/// Open the spool under `data_dir` with the at-rest crypto that `storage`
	/// configures, exactly as the server does. Every operator command that
	/// reads envelopes opens the spool this way: with `encrypt_at_rest` on, a
	/// spool opened without the key cannot read a single envelope.
	pub fn open_configured(
		data_dir: &Path,
		storage: Option<&crate::config::Storage>,
	) -> std::io::Result<Self> {
		let crypto = MessageCrypto::from_config(storage)
			.map_err(|error| std::io::Error::other(format!("spool key: {error}")))?;
		Self::open_with_crypto(data_dir, crypto)
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

	/// Retighten the spool root, `tmp/`, `new/` and the files directly in them
	/// to `0700`/`0600`, and return how many files changed. Safe to call
	/// repeatedly. Links are never followed. The server calls it once at
	/// start-up through [`FsSpool::open_audited`]; `epistle status` only counts.
	pub fn audit_permissions(&self) -> std::io::Result<u64> {
		#[cfg(unix)]
		return audit_permissions(&self.root);
		#[cfg(not(unix))]
		let _ = self;
		#[cfg(not(unix))]
		Ok(0)
	}

	/// Walk the spool without modifying it and return the number of files
	/// and directories whose permissions are looser than `0600` (files) or
	/// `0700` (directories). Used by the `spool` status check, which must
	/// observe the on-disk state without fixing it.
	pub fn count_loose_permissions(&self) -> std::io::Result<u64> {
		#[cfg(unix)]
		return count_loose_permissions(&self.root);
		#[cfg(not(unix))]
		let _ = self;
		#[cfg(not(unix))]
		Ok(0)
	}

	/// [`FsSpool::count_loose_permissions`] for the spool under `data_dir`,
	/// without opening it: an observer such as `epistle status`, possibly run
	/// as root, must never create a spool directory. `0` when there is no
	/// spool yet.
	pub fn count_loose_permissions_in(data_dir: &Path) -> std::io::Result<u64> {
		let root = data_dir.join("spool");
		if !fs::symlink_metadata(&root).is_ok_and(|meta| meta.is_dir()) {
			return Ok(0);
		}
		count_loose_permissions(&contained(data_dir, &root)?)
	}

	/// Open the spool under `data_dir`, encrypting/decrypting the raw message
	/// (`.eml`) files and the envelope (`.json`) sidecar through `crypto`. The
	/// envelope is sealed with ChaCha20-Poly1305 and bound to the message id as
	/// associated data, so one message's envelope is never read as another's.
	/// The body is not bound to its id. The server starts through
	/// [`FsSpool::open_audited`], which also retightens a spool written before
	/// the mode was pinned to `0600`/`0700`.
	pub fn open_with_crypto(data_dir: &Path, crypto: MessageCrypto) -> std::io::Result<Self> {
		let root = contained(data_dir, &data_dir.join("spool"))?;
		let spool = FsSpool { root, crypto };
		create_spool_dir(&spool.root)?;
		Ok(spool)
	}

	/// [`FsSpool::open_with_crypto`] for the server start-up: retighten any
	/// spool path looser than owner-only and log how many files changed. A
	/// spool whose permissions cannot be checked or fixed is refused, so the
	/// server never starts on a spool that may be readable by other users.
	pub fn open_audited(data_dir: &Path, crypto: MessageCrypto) -> std::io::Result<Self> {
		let spool = Self::open_with_crypto(data_dir, crypto)?;
		match spool.audit_permissions() {
			Ok(0) => {}
			Ok(fixed) => {
				tracing::info!("tightened {fixed} spool file permissions to owner-only")
			}
			Err(error) => {
				return Err(std::io::Error::new(
					error.kind(),
					format!("spool permission audit failed, refusing to start: {error}"),
				));
			}
		}
		Ok(spool)
	}

	/// Persist one message crash-safely and return its spool id.
	///
	/// Both files are first written and fsynced under `tmp/`, then renamed
	/// into `new/` , envelope last, so a visible envelope guarantees a
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
		self.store_with(
			message,
			id,
			&StoreOptions {
				account,
				extra,
				class: crate::evidence::MailClass::Personal,
				evidence: None,
				retain_days: 0,
			},
		)
	}

	/// Store `message` under `id` with `options`. Both files are written and
	/// synced under `tmp/` first. Then the evidence hook, when there is one,
	/// runs on the exact bytes queued: it writes the acceptance record, and
	/// only when it succeeds are the files renamed into `new/`, envelope last,
	/// where the worker can see them. A hook failure removes the staged files
	/// and is returned, so nothing is queued that has no record. A crash
	/// between the hook and the renames leaves the staged files for
	/// [`FsSpool::leftovers`] to find at the next start.
	pub fn store_with(
		&self,
		message: &AcceptedMessage,
		id: Uuid,
		options: &StoreOptions<'_>,
	) -> std::io::Result<Uuid> {
		let account = options
			.account
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
			extra: options.extra.clone(),
			class: options.class,
			evidence: options.evidence.is_some(),
			retain_days: options.retain_days,
			outcomes_pending: Vec::new(),
		};

		let tmp_message = self.entry_file(SpoolDir::Tmp, id, MessageExt::Eml)?;
		let tmp_envelope = self.entry_file(SpoolDir::Tmp, id, MessageExt::Json)?;
		let final_message = self.entry_file(SpoolDir::New, id, MessageExt::Eml)?;
		let final_envelope = self.entry_file(SpoolDir::New, id, MessageExt::Json)?;

		write_sync(&tmp_message, &self.crypto.encode(&message.data)?)?;
		let envelope_bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		let envelope_sealed = self
			.crypto
			.encode_with_aad(&envelope_bytes, id.as_bytes())?;
		write_sync(&tmp_envelope, &envelope_sealed)?;
		if let Some(record) = options.evidence
			&& let Err(error) = record(&message.data)
		{
			let _ = fs::remove_file(&tmp_envelope);
			let _ = fs::remove_file(&tmp_message);
			return Err(error);
		}
		#[cfg(test)]
		if std::env::var_os("EPISTLE_TEST_ABORT_AFTER_EVIDENCE").is_some() {
			// The crash test: die between the evidence record and the queue.
			std::process::abort();
		}
		fs::rename(&tmp_message, &final_message)?;
		fs::rename(&tmp_envelope, &final_envelope)?;
		Ok(id)
	}

	/// Load one spooled entry by id.
	pub fn load(&self, id: Uuid) -> std::io::Result<SpoolEntry> {
		let envelope = self.load_envelope(id)?;
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
	///
	/// Accepts envelopes sealed with the AEAD as well as the legacy plaintext
	/// form written before `encrypt_at_rest` was turned on. When a plaintext
	/// envelope is read under encryption-enabled, it is rewritten encrypted in
	/// place atomically, so subsequent loads go through the AEAD path.
	pub fn load_envelope(&self, id: Uuid) -> std::io::Result<Envelope> {
		let bytes =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		let (envelope, decrypted) = self.decode_envelope_bytes(id, &bytes)?;
		if decrypted == DecodedEnvelope::Plaintext {
			self.maybe_migrate_envelope(id, &bytes)?;
		}
		Ok(envelope)
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
		let mut envelope = self.read_envelope_unlocked(id)?;
		edit(&mut envelope);
		let tmp = self.path_in(
			&Path::new(SpoolDir::Tmp.name()).join(format!("{id}.{}.json", Uuid::now_v7())),
		)?;
		let bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		let sealed = self.crypto.encode_with_aad(&bytes, id.as_bytes())?;
		let written = write_sync(&tmp, &sealed)
			.and_then(|()| fs::rename(&tmp, self.entry_file(SpoolDir::New, id, MessageExt::Json)?));
		if let Err(error) = written {
			let _ = fs::remove_file(&tmp);
			return Err(error);
		}
		Ok(envelope)
	}

	/// Read an envelope file's bytes and decode it. The returned flag tells
	/// the caller whether the bytes were plaintext (caller should migrate)
	/// or already sealed (nothing to do).
	fn decode_envelope_bytes(
		&self,
		id: Uuid,
		bytes: &[u8],
	) -> std::io::Result<(Envelope, DecodedEnvelope)> {
		if bytes.starts_with(crate::storage::MAGIC) {
			let plaintext = self
				.crypto
				.decode_with_aad(bytes, id.as_bytes())
				.map_err(|error| std::io::Error::other(format!("spool envelope: {error}")))?;
			let envelope: Envelope =
				serde_json::from_slice(&plaintext).map_err(std::io::Error::other)?;
			Ok((envelope, DecodedEnvelope::Sealed))
		} else {
			let envelope: Envelope =
				serde_json::from_slice(bytes).map_err(std::io::Error::other)?;
			Ok((envelope, DecodedEnvelope::Plaintext))
		}
	}

	/// Read and decode an envelope without taking the lock and without
	/// migrating it. Only `update_envelope` calls this: it already holds the
	/// lock and rewrites the envelope sealed itself, so a migration here would
	/// wait on that same lock forever.
	fn read_envelope_unlocked(&self, id: Uuid) -> std::io::Result<Envelope> {
		let bytes =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		let (envelope, _) = self.decode_envelope_bytes(id, &bytes)?;
		Ok(envelope)
	}

	/// If encryption is on and the on-disk envelope is plaintext, rewrite it
	/// encrypted in place. The rewrite goes through `tmp/<uuid>.<uuid>.json`
	/// and is renamed over the old one, so a reader that happens to look at
	/// the file mid-rewrite sees either the old plaintext or the new sealed
	/// envelope, never a half-written file.
	fn maybe_migrate_envelope(&self, id: Uuid, plain: &[u8]) -> std::io::Result<()> {
		if !self.crypto.enabled() {
			return Ok(());
		}
		let _guard = self.lock()?;
		let on_disk =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		if on_disk.starts_with(crate::storage::MAGIC) {
			// Another writer migrated it between our decode and our write.
			return Ok(());
		}
		if on_disk != plain {
			// The envelope on disk no longer matches what we just decoded
			// (someone wrote a newer one). Skip: rewriting over a newer
			// envelope would be a lost update.
			return Ok(());
		}
		let tmp = self.path_in(
			&Path::new(SpoolDir::Tmp.name()).join(format!("{id}.{}.json", Uuid::now_v7())),
		)?;
		let sealed = self.crypto.encode_with_aad(plain, id.as_bytes())?;
		let written = write_sync(&tmp, &sealed)
			.and_then(|()| fs::rename(&tmp, self.entry_file(SpoolDir::New, id, MessageExt::Json)?));
		if let Err(error) = written {
			let _ = fs::remove_file(&tmp);
			return Err(error);
		}
		Ok(())
	}

	/// Take the exclusive spool lock; it is released when the guard drops. The
	/// lock file is owner-only too, so a successful `flock` does not advertise
	/// its existence to other users.
	pub(super) fn lock(&self) -> std::io::Result<fs::File> {
		let mut options = fs::OpenOptions::new();
		options.create(true).truncate(false).write(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(FILE_MODE);
		}
		let file = options.open(self.path_in(Path::new("lock"))?)?;
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
	///
	/// An entry whose outcomes the evidence log has not taken yet is not
	/// removed: that would erase the only trace of a delivery that was made.
	pub fn remove(&self, id: Uuid) -> std::io::Result<()> {
		self.remove_with(id, |_| Ok(())).map(|_| ())
	}

	/// Run `work` while the queue holds nothing under `id`, with the spool's
	/// lock kept for as long as it runs, so a retry cannot queue the message
	/// between the check and the work. Only a file that is not there is an
	/// entry that is not there: a file that cannot be looked at (a link in its
	/// place, permissions, a fault) is an entry that may be, and the work is not
	/// done. Nothing is decoded, so an envelope that cannot be read still counts.
	pub fn while_absent<T>(
		&self,
		id: Uuid,
		work: impl FnOnce() -> std::io::Result<T>,
	) -> std::io::Result<T> {
		let _guard = self.lock()?;
		for ext in [MessageExt::Json, MessageExt::Eml] {
			match fs::symlink_metadata(self.entry_file(SpoolDir::New, id, ext)?) {
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(error),
				Ok(_) => {
					return Err(std::io::Error::new(
						std::io::ErrorKind::AlreadyExists,
						"the queue holds this entry",
					));
				}
			}
		}
		work()
	}

	/// [`remove`](Self::remove), calling `before` with the envelope as it is
	/// under the spool's lock, and removing the entry only if it returns `Ok`.
	/// Reading the envelope, deciding and unlinking are one step: nothing can
	/// change the entry between them, so what `before` writes about it is what
	/// is removed. Returns the envelope that was removed.
	pub fn remove_with(
		&self,
		id: Uuid,
		before: impl FnOnce(&Envelope) -> std::io::Result<()>,
	) -> std::io::Result<Envelope> {
		let _guard = self.lock()?;
		let envelope = self.read_envelope_unlocked(id)?;
		if !envelope.outcomes_pending.is_empty() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::ResourceBusy,
				"the entry has evidence outcomes waiting to be written: it stays until they are",
			));
		}
		before(&envelope)?;
		// Envelope first: a message file without an envelope is invisible.
		fs::remove_file(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		fs::remove_file(self.entry_file(SpoolDir::New, id, MessageExt::Eml)?)?;
		Ok(envelope)
	}
}

impl MessageSink for FsSpool {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.submit(message, Uuid::now_v7(), "", &Submission::default())
	}

	fn submit(
		&self,
		message: AcceptedMessage,
		queue_id: Uuid,
		account: &str,
		submission: &Submission,
	) -> Result<(), SinkError> {
		// The spool alone writes no acceptance: mail whose evidence is
		// mandatory goes through the routing sink that does.
		if submission.class.evidence_mandatory() {
			return Err(SinkError::EvidenceUnavailable(
				"the spool keeps no evidence".into(),
			));
		}
		let options = StoreOptions {
			account: Some(account),
			extra: &submission.extra,
			class: submission.class,
			evidence: None,
			retain_days: 0,
		};
		self.store_with(&message, queue_id, &options)
			.map(|_| ())
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}
}

#[path = "spool_leftovers.rs"]
pub(super) mod leftovers;

#[cfg(test)]
#[path = "spool_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "spool_tests_edit.rs"]
mod tests_edit;

#[cfg(all(test, unix))]
#[path = "spool_tests_absent.rs"]
mod tests_absent;

#[cfg(test)]
#[path = "spool_tests_perms.rs"]
mod tests_perms;

#[cfg(test)]
#[path = "spool_tests_env_crypto.rs"]
mod tests_env_crypto;
