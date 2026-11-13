//! The store itself: its pool, the instance key tokens are hashed under, and
//! the state its clones share.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use sqlx::PgPool;

use crate::antispam::bayes;
use crate::antispam::learning::LearnLimits;
use crate::antispam::shared_training::SharedTraining;
use crate::storage::load_or_create_key_file;

/// The corpus key filename under the data directory.
pub(super) const KEY_FILE: &str = "bayes-corpus.key";

/// The set of scope names whose removal is in flight or whose purge has
/// just committed. The training worker consults the set before any
/// `INSERT` so a job that drained between a removal's start and its
/// commit cannot recreate rows the purge is dropping. The handle is
/// shared with every clone of the [`BayesStore`] so all training paths
/// see the same state.
pub type TombstoneSet = Arc<Mutex<HashSet<String>>>;

/// A fresh, empty tombstone set for tests and constructors that have
/// no other source of one.
pub fn new_tombstone_set() -> TombstoneSet {
	Arc::new(Mutex::new(HashSet::new()))
}

/// A PostgreSQL-backed Bayesian corpus that stores tokens as keyed hashes.
#[derive(Clone)]
pub struct BayesStore {
	pub(in crate::antispam) pool: PgPool,
	/// The keyed hash of tokens, built once from the instance key.
	pub(in crate::antispam) mac: ring::hmac::Key,
	/// Scopes whose removal is currently happening, or has just
	/// committed, so a training worker that has already read its
	/// message off disk drops the job rather than recreating the
	/// rows the purge is dropping. See [`BayesStore::train`].
	pub(in crate::antispam) tombstones: TombstoneSet,
	/// Serializes `train` and `forget_scope` against each other within
	/// this process so a worker that passed the tombstone check cannot
	/// race the DELETE commit. Training is infrequent, so holding it
	/// across the SQL is a fine trade for closing the window the
	/// tombstone set alone cannot. The Mutex is per-instance: a removal
	/// run from the CLI does not see the server's training worker
	/// (different processes, different Mutexes); the cross-process
	/// limit is named on [`BayesStore::forget_scope`].
	pub(in crate::antispam) scope_lock: Arc<tokio::sync::Mutex<()>>,
	/// The queue and workers that train the shared corpus from SMTP,
	/// started by the first job. Clones share it.
	pub(super) shared: Arc<OnceLock<SharedTraining>>,
	/// The ceilings of [`BayesStore::learn`].
	pub(in crate::antispam) limits: LearnLimits,
}

impl BayesStore {
	/// Open the store, loading the token key from `data_dir` or generating and
	/// persisting a fresh `0600` key on first use.
	pub fn open(pool: PgPool, data_dir: &Path) -> std::io::Result<Self> {
		let key = load_or_create_key_file(data_dir, KEY_FILE)?;
		Ok(BayesStore {
			pool,
			mac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
			tombstones: new_tombstone_set(),
			scope_lock: Arc::new(tokio::sync::Mutex::new(())),
			shared: Arc::new(OnceLock::new()),
			limits: LearnLimits::default(),
		})
	}

	/// Build a store with an explicit key (tests). The tombstone set
	/// starts empty: callers can populate it through [`BayesStore::tombstones`]
	/// when they want to simulate an in-flight removal.
	pub fn with_key(pool: PgPool, key: [u8; 32]) -> Self {
		BayesStore {
			pool,
			mac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
			tombstones: new_tombstone_set(),
			scope_lock: Arc::new(tokio::sync::Mutex::new(())),
			shared: Arc::new(OnceLock::new()),
			limits: LearnLimits::default(),
		}
	}

	/// This store without the shared-training queue: same pool, key,
	/// tombstones and lock. The workers hold one, so that the queue's
	/// sender is not kept alive by the workers it feeds.
	pub(super) fn detached(&self) -> Self {
		BayesStore {
			pool: self.pool.clone(),
			mac: self.mac.clone(),
			tombstones: self.tombstones.clone(),
			scope_lock: self.scope_lock.clone(),
			shared: Arc::new(OnceLock::new()),
			limits: self.limits,
		}
	}

	/// This store with other ceilings for [`BayesStore::learn`].
	pub fn with_learn_limits(mut self, limits: LearnLimits) -> Self {
		self.limits = limits;
		self
	}

	/// The shared tombstone set the training worker consults before
	/// every INSERT. Production keeps the set empty except inside
	/// [`BayesStore::forget_scope`]; tests use it to drive the
	/// race-condition test above without a database.
	pub fn tombstones(&self) -> &TombstoneSet {
		&self.tombstones
	}

	/// The stored (hashed) form of a token.
	pub(in crate::antispam) fn hash(&self, token: &str) -> String {
		hex(&self.tag(token))
	}

	/// The keyed fingerprint of a token, the raw bytes of [`BayesStore::hash`].
	pub(super) fn tag(&self, token: &str) -> bayes::TokenTag {
		let tag = ring::hmac::sign(&self.mac, token.as_bytes());
		let mut out = [0u8; 32];
		out.copy_from_slice(tag.as_ref());
		out
	}
}

/// The stored form of a token: a keyed HMAC-SHA256, hex-encoded. Deterministic
/// (so lookups work) but irreversible without the key (so a database leak does
/// not reveal the words).
#[cfg(test)]
pub(super) fn hash_token(key: &[u8], token: &str) -> String {
	let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
	hex(ring::hmac::sign(&mac, token.as_bytes()).as_ref())
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
	bytes.iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	})
}
