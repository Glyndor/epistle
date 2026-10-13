//! Per-snapshot mailbox operations: open / read / STORE / EXPUNGE.
//!
//! The [`Snapshot`] type lives in [`super::mailbox`]; this module owns the
//! `impl` block so the mailbox module file stays under the per-file line
//! limit.

use super::changelog::{Change, Op};
use super::mailbox::Snapshot;
use crate::util::path_component::{AccountName, AccountRoot, MessageExt, message_file};

impl Snapshot {
	/// Build the snapshot of any existing mailbox, decoding message bodies
	/// through `crypto` on read. Use [`crate::storage::MessageCrypto::disabled`]
	/// for a plaintext store. The retention window defaults to `0` (current
	/// behaviour: an expunge deletes the on-disk files immediately); use
	/// [`Self::open_at`] for the archive-aware path.
	pub fn open(
		data_dir: &std::path::Path,
		account: &str,
		mailbox: &str,
		crypto: &crate::storage::MessageCrypto,
	) -> std::io::Result<Snapshot> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		Self::open_at(data_dir, account, mailbox, crypto, 0, now)
	}

	/// Like [`Self::open`], but with an explicit retention window (days) and
	/// unix time used as the archive sidecar timestamp. Production callers
	/// sample the wall clock; tests inject a fixed value so the sidecar's
	/// timestamp is deterministic.
	pub fn open_at(
		data_dir: &std::path::Path,
		account: &str,
		mailbox: &str,
		crypto: &crate::storage::MessageCrypto,
		retention_days: u64,
		now: u64,
	) -> std::io::Result<Snapshot> {
		let _warnings = crate::util::fs_walk::warning_scope();
		let account_name = AccountName::new(account)?;
		let account_dir = super::mailbox::mailbox_dir(data_dir, account_name.as_str(), mailbox)
			.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
		crate::util::fs_walk::check_directories(&account_dir)?;
		let account_root = account_name.root(data_dir)?;
		let uid_validity = super::uidvalidity::read_or_init(&account_dir, &account_root);
		// Fast path: a fresh metadata index whose stamp matches the current
		// mailbox generation lets us skip the per-message sidecar reads. Any
		// doubt (missing, stale, corrupt, wrong version) falls through to the
		// authoritative scan below — the filesystem is always the truth.
		let generation = super::index::current_generation(&account_dir);
		if let Some(loaded) = super::index::load(&account_dir, generation) {
			let uid_next = super::uid::read_counter(&account_dir) + 1;
			return Ok(Snapshot {
				account_dir,
				account_root,
				mailbox: mailbox.to_string(),
				messages: loaded,
				uid_validity,
				uid_next,
				highest_modseq: generation.0,
				crypto: crypto.clone(),
				retention_days,
				now,
				#[cfg(test)]
				loaded_from_index: true,
			});
		}
		let scanned = super::scan::scan_mailbox(&account_dir, crypto)?;
		// HIGHESTMODSEQ is the persisted counter, never below any message's.
		let highest_modseq = super::modseq::read_counter(&account_dir)
			.max(scanned.iter().map(|m| m.modseq).max().unwrap_or(1))
			.max(1);
		let uid_next = super::uid::read_counter(&account_dir) + 1;
		// Persist a fresh index stamped with the generation observed before
		// the scan (the scan only reads the filesystem and assigns UIDs, so
		// the stamp is unchanged). A failed index write must not fail the
		// open — the snapshot already succeeded from the scan, which is
		// canonical.
		let _ = super::index::write(&account_dir, generation, &scanned);
		Ok(Snapshot {
			account_dir,
			account_root,
			mailbox: mailbox.to_string(),
			messages: scanned,
			uid_validity,
			uid_next,
			highest_modseq,
			crypto: crypto.clone(),
			retention_days,
			now,
			#[cfg(test)]
			loaded_from_index: false,
		})
	}

	/// Whether this snapshot was built from the metadata index (fast path)
	/// rather than the full filesystem scan. Test-only correctness signal.
	#[cfg(test)]
	pub(super) fn loaded_from_index(&self) -> bool {
		self.loaded_from_index
	}

	/// The mailbox's highest mod-sequence (CONDSTORE).
	pub fn highest_modseq(&self) -> u64 {
		self.highest_modseq
	}

	/// UIDs expunged after `modseq` (QRESYNC `VANISHED (EARLIER)`, RFC 7162).
	pub fn vanished_since(&self, modseq: u64) -> Vec<u32> {
		super::vanished::since(&self.account_dir, modseq)
	}

	/// Number of messages in the snapshot (the highest sequence number plus
	/// expunged messages still in the snapshot's view).
	pub fn len(&self) -> usize {
		self.messages.len()
	}

	/// Maximum used to resolve `*`: highest UID for UID sets, message count
	/// for sequence sets. Empty mailboxes have no matching identifier.
	pub fn max_identifier(&self, uid: bool) -> u32 {
		if uid {
			self.messages().map(|m| m.uid).max().unwrap_or(0)
		} else {
			u32::try_from(self.len()).unwrap_or(u32::MAX)
		}
	}

	/// Whether the snapshot has no messages.
	pub fn is_empty(&self) -> bool {
		self.messages.is_empty()
	}

	/// A placeholder snapshot with no messages and no on-disk backing. Used
	/// by [`crate::imap::session::Session`] to swap a live snapshot out while
	/// it re-borrows the session to open a fresh one (the value is always
	/// replaced before the method returns, so its contents are never observed).
	pub fn empty() -> Snapshot {
		Snapshot {
			account_dir: std::path::PathBuf::new(),
			account_root: AccountRoot::placeholder(),
			mailbox: String::new(),
			messages: Vec::new(),
			uid_validity: 0,
			uid_next: 1,
			highest_modseq: 1,
			crypto: crate::storage::MessageCrypto::disabled(),
			retention_days: 0,
			now: 0,
			#[cfg(test)]
			loaded_from_index: false,
		}
	}

	/// The mailbox's UIDVALIDITY (RFC 9051 §2.3.1.1): a 32-bit value that
	/// MUST NOT change while UIDs remain valid. Re-assignment makes every
	/// UID previously issued for this mailbox obsolete.
	pub fn uid_validity(&self) -> u32 {
		self.uid_validity
	}

	/// Iterator over all messages in sequence order.
	pub fn messages(&self) -> impl Iterator<Item = &super::mailbox::MessageRef> {
		self.messages.iter()
	}

	/// Next UID a new message would get (the persisted counter, never reused).
	pub fn uid_next(&self) -> u32 {
		self.uid_next
	}

	/// Message by 1-based sequence number.
	pub fn by_sequence(&self, sequence: u32) -> Option<&super::mailbox::MessageRef> {
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
	pub fn read(&self, message: &super::mailbox::MessageRef) -> std::io::Result<Vec<u8>> {
		let stored = crate::util::fs_walk::read(self.message_path(message)?)?;
		self.crypto.decode(&stored)
	}

	/// The on-disk path of a message: the worker's read step names this file
	/// rather than copying the bytes at STORE time, so the protocol reply
	/// never has to wait for the body to be loaded into memory.
	pub fn message_path(
		&self,
		message: &super::mailbox::MessageRef,
	) -> std::io::Result<std::path::PathBuf> {
		message_file(&self.account_dir, message.id(), MessageExt::Eml)
	}

	/// Replace the flags of the message at `sequence` (1-based), persisting
	/// crash-safely. Returns the new flag set.
	pub fn store_flags(
		&mut self,
		sequence: u32,
		flags: Vec<super::mailbox::Flag>,
	) -> std::io::Result<&[super::mailbox::Flag]> {
		let index = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
			.ok_or_else(|| std::io::Error::other("no such message"))?;
		// A STORE that does not change the flag set must not touch the disk or
		// advance the mod-sequence (RFC 7162: only an actual change bumps MODSEQ).
		// Skipping the sidecar rewrite + two counter writes removes the
		// write-amplification of the common "re-mark \Seen" pattern.
		if super::flags::flags_equal(&self.messages[index].flags, &flags) {
			return Ok(&self.messages[index].flags);
		}
		let id = self.messages[index].id;
		super::flags::write_flags(&self.account_dir, id, &flags)?;
		// A flag change advances the mailbox mod-sequence and stamps the message.
		let modseq = super::modseq::next_counter(&self.account_dir)?;
		let _ = super::modseq::write_message(&self.account_dir, id, modseq);
		self.highest_modseq = self.highest_modseq.max(modseq);
		let seen = super::mailbox::Flag::Seen;
		let unread_changed = self.messages[index].flags.contains(&seen) != flags.contains(&seen);
		self.messages[index].flags = flags;
		self.messages[index].modseq = modseq;
		let mut changes = vec![Change::email(Op::Updated, id)];
		if unread_changed {
			changes.push(Change::mailbox(Op::Updated, &self.mailbox));
		}
		super::changelog::note(self.account_root.as_path(), &changes);
		Ok(&self.messages[index].flags)
	}

	/// Re-read the flags and mod-sequence of the message at `sequence` from
	/// its sidecars, so a STORE that adds or removes flags applies to what
	/// another session left there rather than to this snapshot's copy.
	/// Returns `false` when the message is no longer on disk.
	pub fn reload_flags(&mut self, sequence: u32) -> bool {
		let Some(index) = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
		else {
			return false;
		};
		let id = self.messages[index].id;
		if !message_file(&self.account_dir, id, MessageExt::Eml).is_ok_and(|path| path.exists()) {
			return false;
		}
		self.messages[index].flags = super::flags::read_flags(&self.account_dir, id);
		self.messages[index].modseq = super::modseq::read_message(&self.account_dir, id);
		true
	}

	/// Give every message this snapshot shares with `known` the flags and
	/// mod-sequence `known` has for it: the client has not been told about
	/// a change yet, so the next refresh that reports flags still sees it.
	pub fn keep_flags_of(&mut self, known: &Snapshot) {
		let told: std::collections::HashMap<u32, &super::mailbox::MessageRef> = known
			.messages
			.iter()
			.map(|message| (message.uid, message))
			.collect();
		for message in &mut self.messages {
			if let Some(old) = told.get(&message.uid) {
				message.flags.clone_from(&old.flags);
				message.modseq = old.modseq;
			}
		}
	}

	/// Remove one message (file + sidecar) by sequence number.
	pub fn remove_at(&mut self, sequence: u32) -> std::io::Result<()> {
		let index = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
			.ok_or_else(|| std::io::Error::other("no such message"))?;
		let uid = self.messages[index].uid;
		self.take_where(|message| message.uid == uid);
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

	/// Remove the messages whose UID is in `uids`, regardless of the
	/// `\Deleted` flag. Used by REPLACE (RFC 8508), which must take
	/// ownership of a specific message by UID; the client has not had
	/// a chance to set `\Deleted` on the replacement target. Returns
	/// the sequence numbers that were removed, in increasing order.
	pub fn remove_uids(&mut self, uids: &[u32]) -> std::io::Result<Vec<u32>> {
		let removed = self.take_where(|message| uids.contains(&message.uid));
		if !removed.is_empty() {
			super::vanished::record_advancing(&self.account_dir, uids);
		}
		Ok(removed.into_iter().map(|(sequence, _)| sequence).collect())
	}

	/// Expunge every `\Deleted` message whose UID passes `keep`, logging the
	/// vanished UIDs for QRESYNC.
	fn expunge_where(&mut self, keep: impl Fn(u32) -> bool) -> std::io::Result<Vec<u32>> {
		let removed = self.take_where(|message| {
			message.flags.contains(&super::mailbox::Flag::Deleted) && keep(message.uid)
		});
		let vanished: Vec<u32> = removed.iter().map(|(_, uid)| *uid).collect();
		super::vanished::record_advancing(&self.account_dir, &vanished);
		Ok(removed.into_iter().map(|(sequence, _)| sequence).collect())
	}

	/// Take every message `doomed` selects out of the snapshot in a single
	/// pass, removing its files, and return `(sequence, uid)` for each. The
	/// sequence is the one valid when that removal is announced: removing an
	/// earlier message has already renumbered the ones after it.
	fn take_where(
		&mut self,
		mut doomed: impl FnMut(&super::mailbox::MessageRef) -> bool,
	) -> Vec<(u32, u32)> {
		let mut messages = std::mem::take(&mut self.messages);
		let mut taken = Vec::new();
		let mut changes = Vec::new();
		let mut position = 0usize;
		messages.retain(|message| {
			let hit = doomed(message);
			if hit {
				self.remove_files(message.id);
				let sequence = u32::try_from(position + 1 - taken.len()).unwrap_or(u32::MAX);
				taken.push((sequence, message.uid));
				changes.push(Change::email(Op::Destroyed, message.id));
			}
			position += 1;
			!hit
		});
		self.messages = messages;
		if !changes.is_empty() {
			changes.push(Change::mailbox(Op::Updated, &self.mailbox));
			super::changelog::note(self.account_root.as_path(), &changes);
		}
		taken
	}

	/// Remove a message's `.eml` and its `.flags`/`.uid` sidecars.
	///
	/// When retention is configured, the files are **moved** into the
	/// account's archive directory instead of deleted, and a `<id>.deleted`
	/// sidecar records when and from which mailbox they came. The original
	/// `flags` and `uid` sidecars move with the message so a restore can
	/// rebuild the same on-disk state without round-tripping through the
	/// mailstore. When archiving fails the files are **left where they are**
	/// and the error is logged: retention is a promise that the mail can be
	/// recovered for that long, and deleting it because the archive was
	/// briefly unwritable breaks exactly the promise the setting makes.
	fn remove_files(&self, id: uuid::Uuid) {
		if self.retention_days > 0 {
			match super::archive::archive_message(
				&self.account_root,
				&self.account_dir,
				&self.mailbox,
				id,
				self.now,
			) {
				Ok(()) => return,
				Err(error) => {
					tracing::error!(
						%error,
						account_root = %crate::log_id::path(self.account_root.as_path()),
						mailbox = %self.mailbox,
						"could not archive an expunged message; leaving it on disk",
					);
					return;
				}
			}
		}
		for ext in [
			MessageExt::Eml,
			MessageExt::Flags,
			MessageExt::Uid,
			MessageExt::Zone,
		] {
			if let Ok(path) = message_file(&self.account_dir, id, ext) {
				let _ = std::fs::remove_file(path);
			}
		}
	}
}
