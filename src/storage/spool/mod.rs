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
mod durability;
use durability::sync_dir_of;
mod permissions;
pub(super) use permissions::write_sync;
use permissions::{FILE_MODE, audit_permissions, count_loose_permissions, create_spool_dir};
mod recipients;
pub use recipients::{RecipientState, RecipientStatus};
mod envelope;
mod envelope_io;
mod store;
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
	/// The hosted domain whose webhook hears about the delivery, decided by
	/// the server (see [`Envelope::owner`]); `None` for the server-wide one.
	pub owner: Option<&'a str>,
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
	/// Resolves the submitting account to the hosted domain that owns what
	/// it queues; without it an entry has no owner.
	owners: Option<crate::directory_store::DirectoryHandle>,
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
	/// Give the spool the directory that says which hosted domain an
	/// authenticated account belongs to, so what it queues through
	/// [`MessageSink::submit`] is owned by that domain's tenant.
	pub fn with_owner_directory(
		mut self,
		directory: crate::directory_store::DirectoryHandle,
	) -> Self {
		self.owners = Some(directory);
		self
	}

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
		let spool = FsSpool {
			root,
			crypto,
			owners: None,
		};
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
		self.remove_with(id, |_, _| Ok(())).map(|_| ())
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
	///
	/// The entry is put on hold before `before` runs, and stays on hold unless
	/// `before` fails in a way that says it wrote nothing: what `before` records
	/// about the entry must not be contradicted by a worker delivering it in the
	/// meantime, and a failure that leaves it unknown whether something was
	/// written must not release it. `before` gets the envelope as it was read
	/// (with its own hold, if it had one) and a flag it raises before each write
	/// and lowers only when a failure says nothing was written.
	pub fn remove_with(
		&self,
		id: Uuid,
		before: impl FnOnce(&Envelope, &std::cell::Cell<bool>) -> std::io::Result<()>,
	) -> std::io::Result<Envelope> {
		let _guard = self.lock()?;
		let envelope = self.read_envelope_unlocked(id)?;
		if !envelope.outcomes_pending.is_empty() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::ResourceBusy,
				"the entry has evidence outcomes waiting to be written: it stays until they are",
			));
		}
		let mut held = envelope.clone();
		let now = crate::storage::delivery_log::now_epoch();
		held.hold(now);
		held.cancelling.get_or_insert(now);
		if held.held != envelope.held || held.cancelling != envelope.cancelling {
			self.write_envelope_unlocked(id, &held)?;
		}
		let may_have_written = std::cell::Cell::new(false);
		if let Err(error) = before(&envelope, &may_have_written) {
			if !may_have_written.get() && held != envelope {
				// Nothing was written: the entry goes back as it was.
				if let Err(restore) = self.write_envelope_unlocked(id, &envelope) {
					tracing::error!(%id, %restore, "an entry kept after a refused removal stays on hold");
				}
			}
			return Err(error);
		}
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
		let owner = self
			.owners
			.as_ref()
			.and_then(|directory| crate::webhook::account_owner(&directory.current(), account));
		let options = StoreOptions {
			account: Some(account),
			extra: &submission.extra,
			owner: owner.as_deref(),
			class: submission.class,
			evidence: None,
			retain_days: 0,
		};
		self.store_with(&message, queue_id, &options)
			.map(|_| ())
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}
}

pub(super) mod leftovers;

#[cfg(test)]
mod tests;
