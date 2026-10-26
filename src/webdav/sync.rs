//! The per-collection change log behind RFC 6578 `sync-collection` and the
//! `CS:getctag` property, shared by calendars and addressbooks.
//!
//! Each calendar or addressbook directory holds a `.changelog` file. Its
//! first line is a header, `#epistle-sync <epoch> <base>`, and every other
//! line one change, `<sequence> TAB <name> TAB <0|1>` (1 for a removal),
//! where `name` is the member's file name inside the collection.
//!
//! - The sync token is `urn:epistle:sync:<epoch>-<n>`, `n` the highest
//!   sequence so far. The epoch is chosen when the log is created, so a
//!   token from a collection that was deleted and recreated under the same
//!   name is never mistaken for one of the new collection.
//! - Only the last [`MAX_ENTRIES`] changes are kept. `base` is the sequence
//!   of the newest change dropped, so a token is valid exactly when
//!   `base <= n <= highest`: everything after it is still in the log.
//! - Every write rewrites the log through a sibling temp file, `fsync` and
//!   `rename` and a flush of the directory, so a crash leaves either the old or the new log, never a torn
//!   one. A lock per collection serialises the writers of one log, so two
//!   concurrent PUTs into it never hand out the same sequence, while the
//!   logs of other collections and accounts are not held up by its `fsync`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// The change log's file name inside a collection directory.
pub const CHANGELOG: &str = ".changelog";

/// The temp file a new version of the log is written to before the rename.
const CHANGELOG_TMP: &str = ".changelog.tmp";

/// How many changes the log keeps.
pub const MAX_ENTRIES: usize = 1000;

const TOKEN_PREFIX: &str = "urn:epistle:sync:";

const HEADER: &str = "#epistle-sync";

/// One lock per collection directory, serialising the read-modify-write of
/// that collection's change log in this process.
static WRITERS: LazyLock<std::sync::Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> =
	LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Above this many tracked collections, locks nobody holds are dropped from
/// the map when a new one is added, so it does not grow with every
/// collection ever touched.
const LOCK_MAP_PRUNE_AT: usize = 1024;

/// Take the write lock of `collection`'s change log.
async fn lock_collection(collection: &Path) -> OwnedMutexGuard<()> {
	let lock = {
		let mut locks = WRITERS.lock().unwrap_or_else(|poison| poison.into_inner());
		if locks.len() >= LOCK_MAP_PRUNE_AT && !locks.contains_key(collection) {
			locks.retain(|_, lock| Arc::strong_count(lock) > 1);
		}
		Arc::clone(locks.entry(collection.to_path_buf()).or_default())
	};
	lock.lock_owned().await
}

/// Whether `name` is one of the log's own files, which are bookkeeping and
/// never a member of the collection.
pub fn is_internal(name: &str) -> bool {
	name == CHANGELOG || name == CHANGELOG_TMP
}

/// One recorded change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
	/// The sequence number, strictly increasing within one log.
	pub sequence: u64,
	/// The member's file name inside the collection.
	pub name: String,
	/// `true` when the member was removed.
	pub deleted: bool,
}

/// A collection's change log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
	epoch: String,
	base: u64,
	changes: Vec<Change>,
}

impl Log {
	fn new() -> Self {
		Self {
			epoch: uuid::Uuid::now_v7().simple().to_string(),
			base: 0,
			changes: Vec::new(),
		}
	}

	/// The highest sequence handed out so far.
	pub fn highest(&self) -> u64 {
		self.changes
			.last()
			.map_or(self.base, |change| change.sequence)
	}

	/// The token that names `sequence` of this log, for a reply that stops
	/// there so the client resumes from it.
	pub fn token_at(&self, sequence: u64) -> String {
		format!("{TOKEN_PREFIX}{}-{sequence}", self.epoch)
	}

	/// The current sync token, also used as the `CS:getctag` value.
	pub fn token(&self) -> String {
		format!("{TOKEN_PREFIX}{}-{}", self.epoch, self.highest())
	}

	/// The sequence a token names, when the token was issued by this log and
	/// every change after it is still kept. `None` means the client has to
	/// start over with an empty token.
	pub fn position_of(&self, token: &str) -> Option<u64> {
		let (epoch, n) = token.trim().strip_prefix(TOKEN_PREFIX)?.split_once('-')?;
		let n: u64 = n.parse().ok()?;
		(epoch == self.epoch && self.base <= n && n <= self.highest()).then_some(n)
	}

	/// The members changed after `position`, one entry per name carrying
	/// its latest change, in the order of those latest changes.
	pub fn changed_since(&self, position: u64) -> Vec<Change> {
		let mut latest: Vec<Change> = Vec::new();
		for change in self.changes.iter().filter(|c| c.sequence > position) {
			latest.retain(|seen| seen.name != change.name);
			latest.push(change.clone());
		}
		latest
	}

	fn parse(text: &str) -> Option<Self> {
		let mut lines = text.lines();
		let mut header = lines.next()?.split(' ');
		if header.next()? != HEADER {
			return None;
		}
		let epoch = header.next()?.to_string();
		let base = header.next()?.parse().ok()?;
		let mut changes = Vec::new();
		for line in lines {
			let mut fields = line.split('\t');
			let (Some(sequence), Some(name), Some(deleted)) =
				(fields.next(), fields.next(), fields.next())
			else {
				return None;
			};
			changes.push(Change {
				sequence: sequence.parse().ok()?,
				name: name.to_string(),
				deleted: deleted == "1",
			});
		}
		Some(Self {
			epoch,
			base,
			changes,
		})
	}

	fn render(&self) -> String {
		let mut out = format!("{HEADER} {} {}\n", self.epoch, self.base);
		for change in &self.changes {
			let flag = if change.deleted { 1 } else { 0 };
			out.push_str(&format!("{}\t{}\t{flag}\n", change.sequence, change.name));
		}
		out
	}
}

/// Read the log of `collection`, creating an empty one when there is none
/// yet (a collection made before the log existed, or never written to).
/// `None` only when the log cannot be read or written.
pub async fn load(collection: &Path) -> Option<Log> {
	let _guard = lock_collection(collection).await;
	load_or_create(collection).await
}

async fn load_or_create(collection: &Path) -> Option<Log> {
	match tokio::fs::read_to_string(collection.join(CHANGELOG)).await {
		Ok(text) => Log::parse(&text),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			let log = Log::new();
			save(collection, &log).await.ok()?;
			Some(log)
		}
		Err(_) => None,
	}
}

/// Record changes to members of `collection`: `(file name, removed)` in
/// the order they happened. A failure is logged and otherwise ignored: the
/// member write already succeeded, and a lost entry costs at worst a stale
/// client cache until its next full sync, which an unreadable log forces
/// anyway because every token is then refused.
pub async fn record(collection: &Path, entries: &[(String, bool)]) {
	if entries.is_empty() {
		return;
	}
	let _guard = lock_collection(collection).await;
	let Some(mut log) = load_or_create(collection).await else {
		tracing::warn!(collection = %collection.display(), "webdav change log unreadable");
		return;
	};
	for (name, deleted) in entries {
		let sequence = log.highest() + 1;
		log.changes.push(Change {
			sequence,
			name: name.clone(),
			deleted: *deleted,
		});
	}
	if log.changes.len() > MAX_ENTRIES {
		let dropped: Vec<Change> = log
			.changes
			.drain(..log.changes.len() - MAX_ENTRIES)
			.collect();
		log.base = dropped.last().map_or(log.base, |change| change.sequence);
	}
	if let Err(error) = save(collection, &log).await {
		tracing::warn!(collection = %collection.display(), %error, "webdav change log not written");
	}
}

/// Write `log` to a temp file, flush it to disk, and rename it over the log.
async fn save(collection: &Path, log: &Log) -> std::io::Result<()> {
	let tmp = collection.join(CHANGELOG_TMP);
	let result = async {
		let mut file = tokio::fs::File::create(&tmp).await?;
		file.write_all(log.render().as_bytes()).await?;
		file.sync_all().await?;
		tokio::fs::rename(&tmp, collection.join(CHANGELOG)).await?;
		// The rename itself is only durable once the directory is flushed.
		tokio::fs::File::open(collection).await?.sync_all().await
	}
	.await;
	if result.is_err() {
		let _ = tokio::fs::remove_file(&tmp).await;
	}
	result
}

#[cfg(test)]
async fn lock_for_tests(collection: &Path) -> OwnedMutexGuard<()> {
	lock_collection(collection).await
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "sync_integration_tests.rs"]
mod integration_tests;

#[cfg(test)]
#[path = "sync_propfind_tests.rs"]
mod propfind_tests;
