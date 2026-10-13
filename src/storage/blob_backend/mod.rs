//! Pluggable blob storage. The trait [`BlobBackend`] hides where a blob lives
//! — the local filesystem under `<data_dir>/blobs/` (the default), or an S3
//! bucket when the operator opts in through `[storage.blobs]`.
//!
//! The trait takes a `Uuid` and a `suffix` rather than a `&str`, mirroring
//! [`crate::api::jmap::blob_path`]: a path the type refuses to build from
//! anything but a parsed UUID is a path an arbitrary caller cannot trick into
//! escaping the blob root. The S3 backend encodes the same id in the object
//! key, so the same guard applies on the remote side.
//!
//! The two implementations keep the historical default behaviour intact:
//!
//! - `FsBackend` keeps one partition per account
//!   (`blobs/accounts/<account>/ab/cd/<id>`) and still reads the shared pool
//!   older versions wrote (`blobs/ab/cd/<id>`, then the flat layout), behind
//!   the trait so the upload / download / quota / reclaim code paths no
//!   longer know it is touching a disk.
//! - `S3Backend` does the four verbs an S3 bucket needs — `PutObject`,
//!   `GetObject`, `DeleteObject`, `ListObjectsV2` — over HTTPS, with SigV4
//!   signed by hand (the AWS SDK is a tree of dependencies for four HTTP
//!   calls; SigV4 is small enough that owning it is cheaper than not).

mod fs_backend;
mod s3_backend;
mod sigv4;

pub use fs_backend::FsBackend;
pub use s3_backend::S3Backend;

use std::pin::Pin;

use uuid::Uuid;

/// Type-erased future returned by every [`BlobBackend`] method. Mirrors the
/// pattern [`crate::dns::provider`] uses for DNS providers: object-safe,
/// `Send + Sync`, and the lifetime of the borrow lets the implementation
/// borrow from `&self`.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// Everything a [`BlobBackend`] can fail at.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
	/// Filesystem operation failed (the `FsBackend` path).
	#[error("blob filesystem error: {0}")]
	Io(#[from] std::io::Error),
	/// The remote backend returned an HTTP 401 or 403. Translated to a
	/// distinct variant so a caller can tell "the bucket is locked" from
	/// "the object does not exist"; the upload handler reports a 5xx rather
	/// than a 404 in this case, which is what an operator chasing a wrong
	/// credential actually wants.
	#[error("blob storage authentication failed")]
	Auth,
	/// Any other error from the remote backend: transport-level, non-2xx
	/// status we did not classify, or a body we could not parse. The message
	/// is intentionally low-detail so it does not leak bucket policy or
	/// signed headers into operator-facing logs.
	#[error("blob storage error: {0}")]
	Remote(String),
}

/// The account partition a blob lives in.
///
/// Built only from a name that passes the same check the mailbox storage
/// applies to account directories ([`crate::util::path_component::AccountName`]):
/// one plain path component, never `.` or `..`, no separator or control
/// character. A backend joins it into a path (or an object key) only
/// through this type, so a request cannot steer a blob outside its
/// account's partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobAccount(String);

impl BlobAccount {
	/// Validate `name` as an account partition, `None` when it is not one
	/// plain path component.
	pub fn new(name: &str) -> Option<Self> {
		crate::util::path_component::AccountName::new(name).ok()?;
		Some(Self(name.to_string()))
	}

	/// The validated account name.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

/// What callers can do with a blob store. All four methods are `async`.
///
/// Every blob belongs to one account. New blobs are written into that
/// account's partition; reads look there first and then in the shared pool
/// older versions wrote, where the `.owner` sidecar is what ties a blob to
/// its account. A blob in one account's partition is never found under
/// another account's name.
///
/// `list` returns just the ids whose **payload** is present, in every
/// partition and in the shared pool. Sidecars alone are not listed; the
/// caller that needs them asks for them by id.
pub trait BlobBackend: Send + Sync {
	/// Fetch the bytes for `(account, id, suffix)`. `None` means absent (the
	/// same answer a fresh disk would give); `Err(BlobError)` includes
	/// `Auth`, which the [`crate::storage::BlobError::Auth`] variant carries.
	fn get(&self, account: &BlobAccount, id: Uuid, suffix: &str) -> BoxFuture<'_, Option<Vec<u8>>>;
	/// Write the payload (or sidecar) into the account's partition.
	/// Idempotent: re-writing overwrites.
	fn put(&self, account: &BlobAccount, id: Uuid, suffix: &str, bytes: &[u8])
	-> BoxFuture<'_, ()>;
	/// Remove the payload (or sidecar) from the account's partition and from
	/// the shared pool. Idempotent: removing something absent is `Ok(())`.
	fn delete(&self, account: &BlobAccount, id: Uuid, suffix: &str) -> BoxFuture<'_, ()>;
	/// Every payload id currently stored, in unspecified order.
	fn list(&self) -> BoxFuture<'_, Vec<Uuid>>;
}

/// Build the backend the operator configured, defaulting to `FsBackend`
/// against `data_dir` when no `[storage.blobs]` section is present. The
/// returned trait object is `Send + Sync` so it can live on `ApiState`.
///
/// `S3Backend` requires credentials; a config that names `s3` but resolves
/// to no secret fails closed at construction rather than at the first
/// request, matching the rest of the crate.
pub fn build(
	data_dir: &std::path::Path,
	cfg: Option<&crate::config::BlobBackendConfig>,
) -> std::io::Result<std::sync::Arc<dyn BlobBackend>> {
	match cfg {
		None => Ok(std::sync::Arc::new(FsBackend::new(data_dir.to_path_buf()))),
		Some(crate::config::BlobBackendConfig::Fs) => {
			Ok(std::sync::Arc::new(FsBackend::new(data_dir.to_path_buf())))
		}
		Some(crate::config::BlobBackendConfig::S3(s3_cfg)) => {
			let secret = s3_cfg.resolve_secret()?;
			let backend = S3Backend::new(
				s3_cfg.endpoint.clone(),
				s3_cfg.bucket.clone(),
				s3_cfg.region.clone(),
				s3_cfg.access_key_id.clone(),
				secret,
			);
			Ok(std::sync::Arc::new(backend))
		}
	}
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
