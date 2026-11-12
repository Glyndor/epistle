//! Reading, rewriting and migrating the envelope file of a spooled entry.

use std::fs;
use std::path::Path;

use uuid::Uuid;

use super::*;

/// How an envelope file was stored on disk: sealed under the AEAD with the
/// message id as AAD, or the legacy plaintext written before at-rest
/// encryption covered envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DecodedEnvelope {
	Sealed,
	Plaintext,
}

impl FsSpool {
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
	/// is renamed over the old one, so a reader never sees a partial file, and
	/// the directory that holds the name is synced after the rename, so a
	/// power cut cannot bring the previous envelope back. A missing entry is
	/// reported as `NotFound` and nothing is written.
	pub fn update_envelope(
		&self,
		id: Uuid,
		edit: impl FnOnce(&mut Envelope),
	) -> std::io::Result<Envelope> {
		let _guard = self.lock()?;
		let mut envelope = self.read_envelope_unlocked(id)?;
		edit(&mut envelope);
		self.write_envelope_unlocked(id, &envelope)?;
		Ok(envelope)
	}

	/// Replace the envelope file of `id` with `envelope`, crash-safely. The
	/// caller holds the spool lock.
	pub(super) fn write_envelope_unlocked(
		&self,
		id: Uuid,
		envelope: &Envelope,
	) -> std::io::Result<()> {
		let tmp = self.path_in(
			&Path::new(SpoolDir::Tmp.name()).join(format!("{id}.{}.json", Uuid::now_v7())),
		)?;
		let bytes = serde_json::to_vec(envelope).map_err(std::io::Error::other)?;
		let sealed = self.crypto.encode_with_aad(&bytes, id.as_bytes())?;
		let final_envelope = self.entry_file(SpoolDir::New, id, MessageExt::Json)?;
		let written = write_sync(&tmp, &sealed)
			.and_then(|()| fs::rename(&tmp, &final_envelope))
			.and_then(|()| sync_dir_of(&final_envelope));
		if let Err(error) = written {
			let _ = fs::remove_file(&tmp);
			return Err(error);
		}
		Ok(())
	}

	/// Read an envelope file's bytes and decode it. The returned flag tells
	/// the caller whether the bytes were plaintext (caller should migrate)
	/// or already sealed (nothing to do).
	pub(super) fn decode_envelope_bytes(
		&self,
		id: Uuid,
		bytes: &[u8],
	) -> std::io::Result<(Envelope, DecodedEnvelope)> {
		if crate::storage::is_envelope(bytes) {
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
	pub(super) fn read_envelope_unlocked(&self, id: Uuid) -> std::io::Result<Envelope> {
		let bytes =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		let (envelope, _) = self.decode_envelope_bytes(id, &bytes)?;
		Ok(envelope)
	}

	/// If encryption is on and the on-disk envelope is plaintext, rewrite it
	/// encrypted in place. The rewrite goes through `tmp/<uuid>.<uuid>.json`
	/// and is renamed over the old one, so a reader that happens to look at
	/// the file mid-rewrite sees either the old plaintext or the new sealed
	/// envelope, never a half-written file. The directory that holds the name
	/// is synced after the rename, so the sealed envelope is what a power cut
	/// leaves behind.
	pub(super) fn maybe_migrate_envelope(&self, id: Uuid, plain: &[u8]) -> std::io::Result<()> {
		if !self.crypto.enabled() {
			return Ok(());
		}
		let _guard = self.lock()?;
		let on_disk =
			crate::util::fs_walk::read(self.entry_file(SpoolDir::New, id, MessageExt::Json)?)?;
		if crate::storage::is_envelope(&on_disk) {
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
		let final_envelope = self.entry_file(SpoolDir::New, id, MessageExt::Json)?;
		let written = write_sync(&tmp, &sealed)
			.and_then(|()| fs::rename(&tmp, &final_envelope))
			.and_then(|()| sync_dir_of(&final_envelope));
		if let Err(error) = written {
			let _ = fs::remove_file(&tmp);
			return Err(error);
		}
		Ok(())
	}
}
