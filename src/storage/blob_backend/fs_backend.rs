//! Filesystem implementation of [`BlobBackend`]: one partition per account
//! under `<data_dir>/blobs/accounts/`, sharded two levels by the tail of the
//! UUID, with the shared pool older versions wrote still read as a fallback.
//! Behind a trait so an operator can swap it for [`super::S3Backend`]
//! without code changes.
//!
//! The pathing logic is delegated to [`crate::api::jmap::blob_path`]. Keeping
//! the helpers there means a reader following a blob id to its file ends up
//! at the same module whether the caller is the on-disk backend, a test, or
//! an upgrade tool.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use uuid::Uuid;

use super::BlobError;
use super::{BlobAccount, BlobBackend};
use crate::api::jmap::blob_path;

/// `Send + Sync` future alias specific to this module, kept narrow so the
/// trait surface in `blob_backend.rs` does not grow boilerplate. Uses
/// `'static` because the `BlobBackend` methods take borrowed args that get
/// cloned into the `Arc<Inner>`-style state owned by the future; matches the
/// pattern `OvhProvider::upsert` uses.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// Internal state shared by every async call. Cloned into the `async move`
/// block so the future owns everything it needs (matching the
/// `OvhProvider::upsert` pattern: cheap inner state, `&self` only borrows
/// while it is alive).
struct Inner {
	data_dir: PathBuf,
}

/// The on-disk blob store.
///
/// A payload lives under `<data_dir>/blobs/accounts/<account>/ab/cd/<id>`
/// (sharded by the tail of the id). Reads for an account look in its
/// partition, then in the shared pool (`blobs/ab/cd/<id>`, then the flat
/// `blobs/<id>`) older versions wrote; writes always go to the partition.
pub struct FsBackend {
	inner: Arc<Inner>,
}

impl FsBackend {
	/// Build a backend rooted at `data_dir`. The directory is not created
	/// here; the first write does it, mirroring what the upload handler used
	/// to do (the `dirs::create_dir_all` call before `write`).
	pub fn new(data_dir: PathBuf) -> Self {
		FsBackend {
			inner: Arc::new(Inner { data_dir }),
		}
	}
}

impl BlobBackend for FsBackend {
	fn get(
		&self,
		account: &BlobAccount,
		id: Uuid,
		suffix: &str,
	) -> BoxFuture<'static, Option<Vec<u8>>> {
		let account = account.clone();
		let suffix = suffix.to_string();
		let inner = self.inner.clone();
		Box::pin(async move {
			// The account's partition first, then the shared pool an older
			// version wrote. Another account's partition is never looked at.
			let partitioned = blob_path::account_path(&inner.data_dir, &account, id, &suffix)?;
			for path in [
				partitioned,
				blob_path::read_path(&inner.data_dir, id, &suffix),
			] {
				match std::fs::read(&path) {
					Ok(bytes) => return Ok(Some(bytes)),
					Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
					Err(error) => return Err(BlobError::Io(error)),
				}
			}
			Ok(None)
		})
	}

	fn put(
		&self,
		account: &BlobAccount,
		id: Uuid,
		suffix: &str,
		bytes: &[u8],
	) -> BoxFuture<'static, ()> {
		let account = account.clone();
		let suffix = suffix.to_string();
		let payload = bytes.to_vec();
		let inner = self.inner.clone();
		Box::pin(async move {
			// Always into the account's partition: writing to the shared
			// pool would put the blob back where every account's name can
			// reach it, held back only by its sidecar.
			let path = blob_path::account_path(&inner.data_dir, &account, id, &suffix)?;
			if let Some(parent) = path.parent() {
				std::fs::create_dir_all(parent)?;
			}
			std::fs::write(&path, &payload)?;
			Ok(())
		})
	}

	fn delete(&self, account: &BlobAccount, id: Uuid, suffix: &str) -> BoxFuture<'static, ()> {
		let account = account.clone();
		let suffix = suffix.to_string();
		let inner = self.inner.clone();
		Box::pin(async move {
			// Remove every copy this account could be served: its partition,
			// and the sharded and flat locations of the shared pool, so a
			// stale older copy cannot shadow the deletion.
			let partitioned = blob_path::account_path(&inner.data_dir, &account, id, &suffix)?;
			let sharded = blob_path::write_path(&inner.data_dir, id, &suffix);
			let flat = blob_path::blob_root(&inner.data_dir).join(format!("{id}{suffix}"));
			for path in [partitioned, sharded, flat] {
				match std::fs::remove_file(&path) {
					Ok(()) => {}
					Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
					Err(error) => return Err(BlobError::Io(error)),
				}
			}
			Ok(())
		})
	}

	fn list(&self) -> BoxFuture<'static, Vec<Uuid>> {
		let inner = self.inner.clone();
		Box::pin(async move {
			let walked = blob_path::walk(&inner.data_dir);
			Ok(walked.into_iter().map(|(id, _)| id).collect())
		})
	}
}
