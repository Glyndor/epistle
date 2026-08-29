//! JMAP uploaded-blob storage: the on-disk pool under `<data_dir>/blobs/` and
//! every helper that reads, writes, reclaims or audits it.
//!
//! The JMAP upload/download handlers in the parent module delegate the actual
//! filesystem work here. None of the items below know about axum or HTTP
//! routing — they take a [`crate::storage::BlobBackend`] and return plain
//! `Option<Vec<u8>>` / `io::Result<()>` values that the handlers wrap. The
//! split keeps the HTTP layer small and lets the storage code be tested
//! directly against either backend.

use std::sync::Arc;

use super::blob_path;
use crate::imap::mailbox;
use crate::storage::{BlobBackend, MessageCrypto};

/// Read an uploaded blob by id (rejecting any path separators in the id),
/// decoding the at-rest envelope. Fails closed: a blob that cannot be decrypted
/// is not returned rather than served as ciphertext, and a blob whose `.owner`
/// sidecar does not name the requesting account is not returned either — the
/// sidecar gates cross-account reads of the shared blob pool.
pub(super) async fn read_blob(
	backend: &Arc<dyn BlobBackend>,
	account: &str,
	blob_id: &str,
	crypto: &MessageCrypto,
) -> Option<Vec<u8>> {
	// Parse at the boundary: below this line the id is a `Uuid`, so a path
	// built from it is bound to the configured backend's namespace.
	let blob_id = uuid::Uuid::parse_str(blob_id).ok()?;
	// Owner sidecar is mandatory for every uploaded blob: missing, empty, or
	// mismatching means the blob is not (or no longer) owned by `account`, so
	// it must not be served. Pre-existing blobs from before this gate was
	// introduced get an `.owner` written by the startup backfill; transient
	// uploads that never get referenced stay sidecar-less and become
	// unservable (the reclaim task sweeps them after their TTL anyway).
	let owner_bytes = backend.get(blob_id, ".owner").await.ok()??;
	let owner = String::from_utf8(owner_bytes).ok()?;
	if owner.as_str() != account {
		return None;
	}
	let stored = backend.get(blob_id, "").await.ok()??;
	crypto.decode(&stored).ok()
}

/// Read the recorded media type of an uploaded blob, if any (the `.type`
/// sidecar written at upload time). Returns `None` for stored messages.
pub(super) async fn read_blob_type(
	backend: &Arc<dyn BlobBackend>,
	blob_id: &str,
) -> Option<String> {
	let blob_id = uuid::Uuid::parse_str(blob_id).ok()?;
	let bytes = backend.get(blob_id, ".type").await.ok()??;
	let value = String::from_utf8(bytes).ok()?;
	(!value.is_empty()).then_some(value)
}

/// Suffix written alongside every uploaded blob to record the account that
/// owns it. Mirrors the `.type` sidecar (the media-type sidecar already used
/// for uploaded blobs).
const OWNER_SIDECAR_SUFFIX: &str = ".owner";

/// Write the `.owner` sidecar for an uploaded blob, recording the account that
/// owns it. Used by the upload handler and by the startup backfill.
pub(super) async fn write_blob_owner(
	backend: &Arc<dyn BlobBackend>,
	blob_id: uuid::Uuid,
	account: &str,
) -> Result<(), crate::storage::BlobError> {
	backend
		.put(blob_id, OWNER_SIDECAR_SUFFIX, account.as_bytes())
		.await
}

/// Read the recorded owner of an uploaded blob, if any. Visible to sibling
/// test modules so they can assert on the sidecar without scraping the
/// filesystem in two places.
#[cfg(test)]
pub(crate) async fn read_blob_owner(
	backend: &Arc<dyn BlobBackend>,
	blob_id: &str,
) -> Option<String> {
	let blob_id = uuid::Uuid::parse_str(blob_id).ok()?;
	let bytes = backend.get(blob_id, OWNER_SIDECAR_SUFFIX).await.ok()??;
	let value = String::from_utf8(bytes).ok()?;
	(!value.is_empty()).then_some(value)
}

/// Bytes counted against an account's storage quota: its stored mail (every
/// message across INBOX and folders) plus the uploaded blob store. JMAP blobs
/// live in one shared `<data_dir>/blobs` pool that is not partitioned per
/// account, so the whole pool is counted — a conservative, fail-closed choice
/// that never under-counts usage when enforcing the quota on upload.
///
/// Sizes on the blob side are read directly off the filesystem rather than
/// through the backend: the FS backend's `list()` only returns ids, and the
/// S3 backend operator is expected to manage quota via bucket metrics (S3
/// does not let us efficiently size the whole bucket through the LIST API).
pub fn account_usage_bytes(
	data_dir: &std::path::Path,
	account: &str,
	crypto: &MessageCrypto,
) -> u64 {
	mailbox::account_usage(data_dir, account, crypto).saturating_add(blobs_usage_bytes(data_dir))
}

/// Total size in bytes of the uploaded blob store, counting blob payloads and
/// their `.type` and `.owner` sidecars under `<data_dir>/blobs`.
fn blobs_usage_bytes(data_dir: &std::path::Path) -> u64 {
	let mut total = 0u64;
	for (blob_id, path) in blob_path::walk(data_dir) {
		for candidate in [
			path,
			blob_path::read_path(data_dir, blob_id, ".type"),
			blob_path::read_path(data_dir, blob_id, OWNER_SIDECAR_SUFFIX),
		] {
			if let Ok(meta) = std::fs::metadata(&candidate)
				&& meta.is_file()
			{
				total = total.saturating_add(meta.len());
			}
		}
	}
	total
}

/// Reclaim transient uploaded blobs (RFC 8620 §6.1: an uploaded blob that is
/// not referenced may be deleted). Delete every blob — payload and its `.type`
/// and `.owner` sidecars — whose payload was last modified more than `ttl` ago,
/// returning the number of blobs removed. Only the upload store under
/// `<data_dir>/blobs` is touched; stored mail under `<data_dir>/accounts` is
/// never affected.
pub fn reclaim_blobs(data_dir: &std::path::Path, ttl: std::time::Duration) -> usize {
	let now = std::time::SystemTime::now();
	let mut removed = 0;
	// `walk` yields payloads only, from both the sharded and the flat layout,
	// so a blob written before this change is still reclaimed.
	for (blob_id, path) in blob_path::walk(data_dir) {
		let expired = std::fs::metadata(&path)
			.and_then(|meta| meta.modified())
			.ok()
			.and_then(|modified| now.duration_since(modified).ok())
			.is_some_and(|age| age > ttl);
		if expired {
			let _ = std::fs::remove_file(&path);
			for sidecar in [".type", OWNER_SIDECAR_SUFFIX] {
				let _ = std::fs::remove_file(blob_path::read_path(data_dir, blob_id, sidecar));
			}
			removed += 1;
		}
	}
	removed
}

/// Counts from [`backfill_blob_ownership`]: lets the caller log progress at
/// startup and lets tests verify what the pass actually did without scraping
/// the filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackfillStats {
	/// Stored messages inspected across every account's mailboxes.
	pub scanned: u64,
	/// Sidecars written because they were missing or did not match the
	/// account that owns the message.
	pub written: u64,
	/// Sidecars left untouched because they already named the correct owner.
	pub skipped: u64,
	/// Sidecars that already named a *different* owner — recorded so the
	/// operator can investigate, never overwritten (two distinct accounts
	/// claiming the same UUID is a real anomaly, not something to silently
	/// fix).
	pub conflicts: u64,
	/// Per-message filesystem errors swallowed so a corrupt mailbox does not
	/// abort the pass (the spec: "que no muera si un mensaje esta corrupto").
	pub errors: u64,
}

/// One-shot startup migration: write `.owner` sidecars for every uploaded blob
/// whose corresponding message already lives under the account's mailboxes.
///
/// A stored message's filename UUID is itself a valid `blobId` (RFC 8621 §4.1.1
/// and [`super::objects::email_object`], which returns `blobId: id`). So every `.eml`
/// already implies ownership of its UUID by the account that owns the
/// mailbox, and writing the sidecar here makes those pre-existing uploads
/// servable again after the per-account gate is introduced.
///
/// What this pass deliberately does NOT do:
///
/// - **Scan message bodies for embedded blob references.** RFC 5322 messages
///   can carry any number of UUID-shaped tokens in headers (Message-Id,
///   References, Content-Id...) and inside bodies. Treating every such token
///   as a blob reference would claim ownership of arbitrary UUIDs that may
///   not even exist as blobs in the pool, and in the worst case — when the
///   UUID happens to match another account's blob — would transfer that
///   blob's ownership. The conservative choice is to only register UUIDs the
///   server actually minted as mailbox filenames; future attachment support
///   can extend this pass without touching the security model.
/// - **Rewrite sidecars that already name the correct owner.** Idempotent:
///   re-running on a server whose sidecars are already up-to-date is a no-op
///   (verified by the `mtime_unchanged_on_second_run` test).
/// - **Touch a `.owner` that names a different account.** Logged as a
///   conflict and left alone — two distinct accounts claiming the same UUID
///   is a real anomaly worth investigating, never something to silently
///   resolve by overwriting.
///
/// Errors reading individual mailbox directories or entries are swallowed
/// and counted in [`BackfillStats::errors`] so a single bad message does not
/// abort the whole pass.
pub fn backfill_blob_ownership(data_dir: &std::path::Path, accounts: &[String]) -> BackfillStats {
	let mut stats = BackfillStats::default();
	for account in accounts {
		for mailbox in mailbox::list(data_dir, account) {
			let Some(dir) = mailbox::mailbox_dir(data_dir, account, &mailbox) else {
				stats.errors = stats.errors.saturating_add(1);
				continue;
			};
			let entries = match std::fs::read_dir(&dir) {
				Ok(entries) => entries,
				Err(_) => {
					stats.errors = stats.errors.saturating_add(1);
					continue;
				}
			};
			for entry in entries {
				let entry = match entry {
					Ok(entry) => entry,
					Err(_) => {
						stats.errors = stats.errors.saturating_add(1);
						continue;
					}
				};
				let name = match entry.file_name().to_str() {
					Some(name) => name.to_string(),
					None => continue,
				};
				let Some(stem) = name.strip_suffix(".eml") else {
					continue;
				};
				// A non-UUID filename means the message would not have been
				// accepted by the snapshot; nothing to register.
				// A non-UUID filename means the message would not have been
				// accepted by the snapshot; nothing to register.
				let Ok(blob_id) = uuid::Uuid::parse_str(stem) else {
					continue;
				};
				stats.scanned = stats.scanned.saturating_add(1);
				match ensure_blob_owner(data_dir, blob_id, account) {
					Ok(EnsureOutcome::Written) => {
						stats.written = stats.written.saturating_add(1);
					}
					Ok(EnsureOutcome::AlreadyCorrect) => {
						stats.skipped = stats.skipped.saturating_add(1);
					}
					Ok(EnsureOutcome::Conflict) => {
						stats.conflicts = stats.conflicts.saturating_add(1);
					}
					Err(()) => {
						stats.errors = stats.errors.saturating_add(1);
					}
				}
			}
		}
	}
	stats
}

/// What [`ensure_blob_owner`] did to a blob's `.owner` sidecar.
enum EnsureOutcome {
	/// The sidecar was missing or did not match the expected account; it has
	/// now been written.
	Written,
	/// The sidecar already names the expected account; nothing was touched.
	AlreadyCorrect,
	/// The sidecar names a different account; left alone and reported.
	Conflict,
}

/// Write the `.owner` sidecar only if it is missing or does not match the
/// expected account. Returns the [`EnsureOutcome`] describing what happened,
/// or `Err(())` on a filesystem error so the caller can count it without
/// aborting the whole pass.
fn ensure_blob_owner(
	data_dir: &std::path::Path,
	blob_id: uuid::Uuid,
	account: &str,
) -> Result<EnsureOutcome, ()> {
	// Read through the fallback so a blob still in the flat layout is seen,
	// and write to the shard so the backfill does not recreate the old shape.
	let owner_path = blob_path::read_path(data_dir, blob_id, OWNER_SIDECAR_SUFFIX);
	match std::fs::read_to_string(&owner_path) {
		Ok(existing) if existing == account => Ok(EnsureOutcome::AlreadyCorrect),
		Ok(_) => Ok(EnsureOutcome::Conflict),
		Err(_) if owner_path.exists() => Err(()),
		Err(_) => {
			// The payload file determines whether this sidecar is needed at
			// all: if the blob was uploaded but never persisted under
			// `blobs/`, there is nothing to gate. Skipping the sidecar write
			// in that case avoids creating an `.owner` for a non-existent
			// blob (which would not affect the download check but would
			// inflate the scan count).
			if !blob_path::read_path(data_dir, blob_id, "").exists() {
				Ok(EnsureOutcome::AlreadyCorrect)
			} else {
				let write_to = blob_path::write_path(data_dir, blob_id, OWNER_SIDECAR_SUFFIX);
				if let Some(parent) = write_to.parent() {
					std::fs::create_dir_all(parent).map_err(|_| ())?;
				}
				std::fs::write(&write_to, account.as_bytes()).map_err(|_| ())?;
				Ok(EnsureOutcome::Written)
			}
		}
	}
}
