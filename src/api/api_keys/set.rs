//! The keys the running server accepts: [`ApiKeySet`].

use std::io::ErrorKind;
use std::path::Path;

use super::{ApiKey, ApiKeyFile, grants};
use crate::directory_store::StoreError;
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

/// Hot-swappable, thread-safe view of the keys in `api_keys.toml`.
///
/// The store reads the file at construction; the file watcher calls
/// [`ApiKeySet::reload_file`] whenever it sees a fingerprint change on
/// `api_keys.toml`, so does the API after its own writes, and the bearer middleware reads through [`ApiKeySet::snapshot`]
/// on every request. Holding the snapshot guard across a request is
/// fine: a writer waiting for the lock only blocks new snapshots, never
/// the read that's already running.
///
/// The split between [`ApiKeyStore`](super::ApiKeyStore) (CLI-side, persists on every
/// mutation) and [`ApiKeySet`] (server-side, swaps in memory) keeps the
/// watcher honest: the watcher never has to persist what is already on
/// disk, and the CLI never has to coordinate with the running process.
pub struct ApiKeySet {
	keys: std::sync::RwLock<Vec<ApiKey>>,
	/// Set by a test to have every reload fail, as an unreadable file does.
	#[cfg(test)]
	refusing: std::sync::atomic::AtomicBool,
	/// Run once by the next reload, between reading the file and swapping the
	/// keys, so that a test can hold a reload there.
	#[cfg(test)]
	pause: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl ApiKeySet {
	/// Build an empty set without touching the filesystem. Used by
	/// callers that already have a key file on disk but failed to open
	/// it (e.g. a parse error on startup): the operator can still
	/// recover by editing the file and waiting for the watcher to
	/// reload, instead of being locked out until the next restart.
	pub fn empty() -> Self {
		ApiKeySet {
			keys: std::sync::RwLock::new(Vec::new()),
			#[cfg(test)]
			refusing: Default::default(),
			#[cfg(test)]
			pause: Default::default(),
		}
	}

	/// Open (loading if present) the key set under `data_dir`. A missing
	/// file is an empty set. A file with an unknown scope string fails
	/// closed, the same rule the store's loader applies on startup.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let path = data_dir.join("api_keys.toml");
		let file: ApiKeyFile = match std::fs::read_to_string(&path) {
			Ok(text) => toml::from_str(&text)
				.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => ApiKeyFile::default(),
			Err(error) => return Err(error),
		};
		for key in &file.keys {
			grants::validate_loaded(key)?;
		}
		Ok(ApiKeySet {
			keys: std::sync::RwLock::new(file.keys),
			#[cfg(test)]
			refusing: Default::default(),
			#[cfg(test)]
			pause: Default::default(),
		})
	}

	/// Read `path`, which is `api_keys.toml`, and swap the in-memory keys for
	/// what it holds. A missing file reads as empty text.
	///
	/// The lock the writers of the file take is held from the read to the
	/// swap, so two reloads cannot cross: a reload never puts back keys older
	/// than the ones a later write left, and a key revoked meanwhile stays
	/// out. A caller must not hold that lock already.
	pub fn reload_file(&self, path: &Path) -> std::io::Result<()> {
		let _lock = FileLock::acquire(&lock_path(path))?;
		let text = match std::fs::read_to_string(path) {
			Ok(text) => text,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
			Err(error) => return Err(error),
		};
		self.reload_from(&text)
	}

	/// Swap the in-memory keys from `text`, the contents of `api_keys.toml`.
	/// Re-parses the file format the CLI produces. A parse failure leaves
	/// the running set untouched so a half-written or operator-typo'd file
	/// cannot revoke a key the watcher is mid-swap on. A server that reads the
	/// file uses [`Self::reload_file`], which holds the writers' lock.
	pub(crate) fn reload_from(&self, text: &str) -> std::io::Result<()> {
		#[cfg(test)]
		if self.refusing.load(std::sync::atomic::Ordering::SeqCst) {
			return Err(std::io::Error::other("the test refuses every reload"));
		}
		let file: ApiKeyFile = toml::from_str(text)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
		for key in &file.keys {
			grants::validate_loaded(key)?;
		}
		#[cfg(test)]
		self.paused();
		*self.keys.write().unwrap_or_else(|p| p.into_inner()) = file.keys;
		Ok(())
	}

	/// Acquire a read snapshot of the keys. The guard derefs to the slice
	/// the auth path iterates over; the lock is dropped when the guard
	/// goes out of scope, so callers must not hold it across an `await`.
	pub fn snapshot(&self) -> ApiKeySetSnapshot<'_> {
		ApiKeySetSnapshot {
			guard: self.keys.read().unwrap_or_else(|p| p.into_inner()),
		}
	}

	/// Drop the key `label` from the running set, without reading the file.
	/// A key that is gone from the file must stop being accepted even when
	/// the file cannot be read back into the set.
	pub fn forget(&self, label: &str) {
		let mut keys = self.keys.write().unwrap_or_else(|p| p.into_inner());
		keys.retain(|key| key.label != label);
	}

	/// Have the next reload run `hold` between reading and swapping.
	#[cfg(test)]
	pub(crate) fn pause_next_reload(&self, hold: impl FnOnce() + Send + 'static) {
		*self.pause.lock().expect("pause") = Some(Box::new(hold));
	}

	#[cfg(test)]
	fn paused(&self) {
		let hold = self.pause.lock().expect("pause").take();
		if let Some(hold) = hold {
			hold();
		}
	}

	/// Make every later [`Self::reload_from`] fail.
	#[cfg(test)]
	pub(crate) fn refuse_reloads(&self) {
		self.refusing
			.store(true, std::sync::atomic::Ordering::SeqCst);
	}
}

/// A read-side view of [`ApiKeySet`]. Derefs to a `&[ApiKey]` for the
/// standard `iter().find(...)` pattern the auth path uses; the read lock
/// is released when the guard is dropped.
pub struct ApiKeySetSnapshot<'a> {
	guard: std::sync::RwLockReadGuard<'a, Vec<ApiKey>>,
}

impl std::ops::Deref for ApiKeySetSnapshot<'_> {
	type Target = [ApiKey];
	fn deref(&self) -> &Self::Target {
		&self.guard
	}
}

impl crate::directory_store::file_watcher::ApiKeyReloader for ApiKeySet {
	/// Wire the set into the file watcher. The watcher calls this on every
	/// fingerprint change for `api_keys.toml`; the body is just a thin
	/// adapter over [`ApiKeySet::reload_file`].
	fn reload_api_keys(&self, path: &Path) -> Result<(), StoreError> {
		self.reload_file(path).map_err(|error| match error.kind() {
			// What the file says, as against not being able to read it.
			ErrorKind::InvalidData | ErrorKind::InvalidInput => {
				StoreError::Invalid(error.to_string())
			}
			_ => StoreError::Io(error),
		})
	}
}
