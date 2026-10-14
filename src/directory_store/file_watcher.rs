//! File-system watcher that reloads the dynamic account/alias/masked/
//! app-password stores when an external process edits them on disk.
//!
//! The runtime `AccountStore` already rebuilds its in-memory directory on
//! every in-server mutation. The CLI is a separate process that opens its
//! own [`AccountStore`], mutates it, and exits; it has no way to swap the
//! running server's directory. Without this watcher, a `mail account-add`
//! the operator fires while the server is up looks effective
//! (`accounts.toml` carries the row) but every SMTP / IMAP / API request
//! still hits the pre-edit directory, so the new address gets a 5xx until
//! the container restarts.
//!
//! The watcher fills that gap: a background `tokio` task stats each
//! dynamic-store file on the configured interval, compares the
//! `(mtime, length, inode)` triple against the last good fingerprint, and
//! asks the store to swap the matching in-memory mirror when the triple
//! changes. The store rejects the swap on a parse error, so a half-written
//! or operator-typo'd file never replaces the running directory; the
//! warning fires once per *bad version*, not every poll.
//!
//! Polling every 2 s is the cheapest option that meets the 5 s deadline.
//! The `notify` crate is not a dependency and was not added; the task did
//! not authorise a new crate. `Metadata::modified` plus `len` plus the
//! inode is enough: an atomic `write_secret`-style rename swaps the
//! inode, a content rewrite swaps either mtime or length, and a
//! `chmod`/`chown` does not move any of the three.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::directory_store::AccountStore;
use crate::directory_store::StoreError;

/// The cheap file identity used to short-circuit no-change polls and
/// to dedupe the "still bad" warning. None of the three fields alone is
/// reliable: a `touch` moves mtime without moving content, an atomic
/// rename replaces the inode without moving mtime forward by the wall
/// clock the polling task can see, and a `chmod`/`chown` touches
/// `ctime` (not captured) while leaving every captured field alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Fingerprint {
	/// Modification time as reported by the filesystem, truncated to whole
	/// seconds: the poll loop can outrun nanosecond resolution on some
	/// filesystems, and the triple still changes whenever the file
	/// content does.
	pub mtime_secs: u64,
	/// Byte length, distinguishes a write that left the size alone (so
	/// the file is logically unchanged for our purposes) from one that
	/// did not.
	pub len: u64,
	/// The inode number. An atomic `rename(2)` over the watched path
	/// replaces the inode even when mtime and length would compare
	/// equal, so this is the field that catches a CLI edit in the same
	/// polling interval the writer committed it.
	#[cfg(unix)]
	pub ino: u64,
}

/// Hot-reload target for `api_keys.toml`. The file watcher holds one
/// inside an `Arc<dyn ApiKeyReloader>` so the watcher does not have to
/// import the concrete `ApiKeySet` type from `crate::api`, which would
/// cycle back through `crate::api::state` (and through every module
/// that uses it). The trait lives here, next to the watcher, because
/// the watcher is the only caller; `ApiKeySet` is the only implementor.
pub trait ApiKeyReloader: Send + Sync {
	/// Swap the running key set from `text`, the contents of
	/// `api_keys.toml`. The watcher calls this on every fingerprint
	/// change. A parse failure must leave the running set untouched;
	/// the watcher treats the result the same way it treats the other
	/// `reload_*_from` failures (one warning per bad version).
	fn reload_api_keys_from(&self, text: &str) -> std::io::Result<()>;
}

/// The watched path and the reload step it triggers. One entry per
/// dynamic-store file. Adding a new on-disk sidecar that the runtime
/// directory depends on means adding one entry here and one
/// `reload_*_from` method on [`AccountStore`].
#[derive(Debug, Clone, Copy)]
enum ReloadKind {
	Accounts,
	AppPasswords,
	Masked,
	Aliases,
	ApiKeys,
}

impl ReloadKind {
	fn label(self) -> &'static str {
		match self {
			ReloadKind::Accounts => "accounts.toml",
			ReloadKind::AppPasswords => "app_passwords.toml",
			ReloadKind::Masked => "masked.json",
			ReloadKind::Aliases => "aliases.json",
			ReloadKind::ApiKeys => "api_keys.toml",
		}
	}

	/// Apply `text` to `store` and rebuild the directory. Mirrors the
	/// `persist` + `replace(build_directory())` pair the in-server
	/// mutators run, minus the persist step (the bytes already live on
	/// disk under us).
	fn apply(
		self,
		store: &AccountStore,
		api_keys: Option<&dyn ApiKeyReloader>,
		text: &str,
	) -> Result<(), StoreError> {
		match self {
			ReloadKind::Accounts => store.reload_accounts_from(text),
			ReloadKind::AppPasswords => store.reload_app_passwords_from(text),
			ReloadKind::Masked => store.reload_masked_from(text),
			ReloadKind::Aliases => store.reload_aliases_from(text),
			ReloadKind::ApiKeys => match api_keys {
				Some(reloader) => reloader
					.reload_api_keys_from(text)
					.map_err(|error| StoreError::Invalid(error.to_string())),
				None => {
					// No reloader wired in: nothing to apply, but not
					// an error, the operator has not configured an API
					// listener, so the file is just bytes on disk.
					Ok(())
				}
			},
		}
	}

	/// Read the file for `self` (which may be absent, a missing file
	/// means "no state", not an error) and apply the swap. Returns
	/// `Ok(true)` when the store's running directory was rebuilt,
	/// `Ok(false)` when there was nothing to apply, or the parse error
	/// the swap was rejected on.
	fn apply_from_disk(
		self,
		store: &AccountStore,
		api_keys: Option<&dyn ApiKeyReloader>,
		path: &Path,
	) -> Result<bool, StoreError> {
		match std::fs::read_to_string(path) {
			Ok(text) => {
				self.apply(store, api_keys, &text)?;
				Ok(true)
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				self.apply(store, api_keys, "")?;
				Ok(true)
			}
			Err(error) => Err(StoreError::Io(error)),
		}
	}
}

#[derive(Debug, Clone)]
struct Watch {
	path: PathBuf,
	kind: ReloadKind,
}

/// The change detector. One instance per server process; the server
/// spawns it on `serve` startup and lets it run until shutdown.
pub struct FileWatcher {
	watches: Vec<Watch>,
	/// Last fingerprint successfully applied. `None` means "the file
	/// was absent at the last poll".
	last: HashMap<PathBuf, Option<Fingerprint>>,
	/// Last fingerprint we already warned about. A repeated bad poll
	/// with the same fingerprint stays silent; a brand-new bad version
	/// logs once. Cleared on a successful apply.
	last_warned: HashMap<PathBuf, Option<Fingerprint>>,
	store: Arc<AccountStore>,
	/// Optional hot-reload target for `api_keys.toml`. `None` means the
	/// operator has not configured an API listener, so the file is
	/// parsed (or its absence is noted) but the reload callback is not
	/// invoked. The watcher always polls the file either way, so a
	/// later `with_api_keys` upgrade keeps the same fingerprint cache.
	api_keys: Option<Arc<dyn ApiKeyReloader>>,
	/// The data dir the watcher polls under; cached so the reload
	/// status file is written back to the same root.
	data_dir: PathBuf,
}

/// What one `poll` did, for the integration tests' assertions. The
/// server uses the side effects (directory rebuilt, log emitted) and
/// never observes the value directly.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PollReport {
	/// Each entry corresponds to one watched file. A successful reload
	/// is `Loaded`; a parse failure is `BadParse`; the rest of the file
	/// is unchanged.
	pub events: Vec<PollEvent>,
}

/// One watched file's outcome from a single poll. The split between
/// `Unchanged` (file present, fingerprint stable) and `Absent` (file
/// still missing) lets the tests tell "nothing to do" from
/// "still empty" without having to stat the path themselves.
#[derive(Debug, PartialEq, Eq)]
pub enum PollEvent {
	/// The file's fingerprint changed and the store rebuilt its
	/// directory from the new contents.
	Loaded(PollTarget),
	/// The file changed but the new contents failed to parse; the
	/// store's directory is unchanged.
	BadParse(PollTarget),
	/// The file was unchanged since the last poll: nothing to do.
	Unchanged(PollTarget),
	/// The file was absent and is still absent (or has just appeared
	/// absent). Tracked separately so the test can distinguish "still
	/// empty" from "still present and unchanged".
	Absent(PollTarget),
}

/// Which dynamic-store file a `PollEvent` refers to. Mirrors the
/// on-disk filenames: `accounts.toml`, `app_passwords.toml`,
/// `masked.json`, `aliases.json`, `api_keys.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollTarget {
	/// The `accounts.toml` sidecar.
	Accounts,
	/// The `app_passwords.toml` sidecar.
	AppPasswords,
	/// The `masked.json` sidecar.
	Masked,
	/// The `aliases.json` sidecar.
	Aliases,
	/// The `api_keys.toml` sidecar.
	ApiKeys,
}

impl From<ReloadKind> for PollTarget {
	fn from(kind: ReloadKind) -> Self {
		match kind {
			ReloadKind::Accounts => PollTarget::Accounts,
			ReloadKind::AppPasswords => PollTarget::AppPasswords,
			ReloadKind::Masked => PollTarget::Masked,
			ReloadKind::Aliases => PollTarget::Aliases,
			ReloadKind::ApiKeys => PollTarget::ApiKeys,
		}
	}
}

impl FileWatcher {
	/// Build a watcher over the dynamic-store files under `data_dir`.
	/// The `last` map is seeded with the fingerprint the server saw at
	/// startup, so the first poll only fires when the file moved
	/// between `AccountStore::open` and the first poll.
	pub fn new(data_dir: PathBuf, store: Arc<AccountStore>) -> Self {
		let watches = vec![
			Watch {
				path: data_dir.join("accounts.toml"),
				kind: ReloadKind::Accounts,
			},
			Watch {
				path: data_dir.join("app_passwords.toml"),
				kind: ReloadKind::AppPasswords,
			},
			Watch {
				path: data_dir.join("masked.json"),
				kind: ReloadKind::Masked,
			},
			Watch {
				path: data_dir.join("aliases.json"),
				kind: ReloadKind::Aliases,
			},
			Watch {
				path: data_dir.join("api_keys.toml"),
				kind: ReloadKind::ApiKeys,
			},
		];
		let mut last = HashMap::with_capacity(watches.len());
		let mut last_warned = HashMap::with_capacity(watches.len());
		for watch in &watches {
			let fp = fingerprint(&watch.path);
			last.insert(watch.path.clone(), fp);
			last_warned.insert(watch.path.clone(), None);
		}
		FileWatcher {
			watches,
			last,
			last_warned,
			store,
			api_keys: None,
			data_dir,
		}
	}

	/// Attach a reloader for `api_keys.toml`. Must be called before
	/// [`spawn`](Self::spawn) (and ideally before any poll) so the
	/// watcher's first reload of an already-edited file lands on a
	/// running state. The reloader is held as `Arc<dyn ApiKeyReloader>`
	/// to keep `directory_store` independent of `crate::api`; the
	/// concrete type is `crate::api::ApiKeySet` in production.
	pub fn with_api_keys(mut self, reloader: Arc<dyn ApiKeyReloader>) -> Self {
		self.api_keys = Some(reloader);
		self
	}

	/// Run one poll cycle. Cheap when nothing changed. Returns the
	/// per-file events the cycle produced; the server spawns this in a
	/// loop and ignores the return value.
	pub fn poll(&mut self) -> PollReport {
		let watches: Vec<Watch> = self.watches.clone();
		let mut report = PollReport::default();
		for watch in &watches {
			let event = self.poll_one(watch);
			report.events.push(event);
		}
		report
	}

	fn poll_one(&mut self, watch: &Watch) -> PollEvent {
		let target = watch.kind.into();
		let current = fingerprint(&watch.path);
		let previous = self.last.get(&watch.path).copied().flatten();
		match current {
			Some(now) => {
				if previous == Some(now) {
					// Fingerprint unchanged: nothing to do. The warning
					// tracker is left as-is so a recovered file we
					// already complained about gets one chance to log
					// if it persists across versions.
					if self.last_warned.get(&watch.path).copied().flatten() != previous {
						self.last_warned.insert(watch.path.clone(), previous);
					}
					return PollEvent::Unchanged(target);
				}
				// File moved: read, parse, swap.
				let text = match std::fs::read_to_string(&watch.path) {
					Ok(text) => text,
					Err(error) => {
						tracing::warn!(
							target: "epistle::directory_store::file_watcher",
							file = watch.kind.label(),
							%error,
							"cannot read dynamic-store file for reload",
						);
						self.last.insert(watch.path.clone(), Some(now));
						self.last_warned.insert(watch.path.clone(), Some(now));
						return PollEvent::BadParse(target);
					}
				};
				match watch
					.kind
					.apply(&self.store, self.api_keys.as_deref(), &text)
				{
					Ok(()) => {
						self.last.insert(watch.path.clone(), Some(now));
						self.last_warned.insert(watch.path.clone(), None);
						tracing::info!(
							target: "epistle::directory_store::file_watcher",
							file = watch.kind.label(),
							"reloaded dynamic-store file",
						);
						self.write_status();
						PollEvent::Loaded(target)
					}
					Err(error) => {
						// Record the bad fingerprint as the file's
						// current identity so the next poll with the
						// exact same content reports `Unchanged`
						// instead of `BadParse` again. The warning
						// is logged exactly once per bad version.
						self.last.insert(watch.path.clone(), Some(now));
						let already_warned =
							self.last_warned.get(&watch.path).copied().flatten() == Some(now);
						if !already_warned {
							tracing::warn!(
								target: "epistle::directory_store::file_watcher",
								file = watch.kind.label(),
								%error,
								"dynamic-store file failed to parse; running directory is unchanged",
							);
							self.last_warned.insert(watch.path.clone(), Some(now));
						}
						PollEvent::BadParse(target)
					}
				}
			}
			None => {
				// File absent. Treat the absence as the empty
				// configuration: the store reloads from an empty
				// payload, the directory rebuild reflects it.
				if previous.is_none() {
					// Still absent: no-op.
					return PollEvent::Absent(target);
				}
				match watch
					.kind
					.apply_from_disk(&self.store, self.api_keys.as_deref(), &watch.path)
				{
					Ok(_) => {
						self.last.insert(watch.path.clone(), None);
						self.last_warned.insert(watch.path.clone(), None);
						tracing::info!(
							target: "epistle::directory_store::file_watcher",
							file = watch.kind.label(),
							"reloaded dynamic-store file (now absent)",
						);
						self.write_status();
						PollEvent::Loaded(target)
					}
					Err(error) => {
						tracing::warn!(
							target: "epistle::directory_store::file_watcher",
							file = watch.kind.label(),
							%error,
							"cannot apply absent dynamic-store file; running directory is unchanged",
						);
						PollEvent::BadParse(target)
					}
				}
			}
		}
	}

	/// Spawn the poll loop onto the current Tokio runtime. The task
	/// runs until the runtime drops (server shutdown). Returns the
	/// `JoinHandle` for callers that want to await the loop on
	/// graceful shutdown.
	pub fn spawn(mut self, interval: Duration) -> tokio::task::JoinHandle<()> {
		tokio::spawn(async move {
			let mut ticker = tokio::time::interval(interval);
			ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
			// The first `tick()` fires immediately; skip it so the
			// server has had a chance to bind listeners before the
			// first poll reads the file.
			ticker.tick().await;
			loop {
				ticker.tick().await;
				self.poll();
			}
		})
	}
}

/// The cheapest possible identity for a file. `None` means the file is
/// absent or unreadable; the watcher treats both as "empty state".
fn fingerprint(path: &Path) -> Option<Fingerprint> {
	let metadata = std::fs::metadata(path).ok()?;
	if !metadata.is_file() {
		return None;
	}
	let mtime = metadata.modified().ok()?;
	let mtime_secs = mtime
		.duration_since(SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let len = metadata.len();
	#[cfg(unix)]
	let ino = {
		use std::os::unix::fs::MetadataExt;
		metadata.ino()
	};
	#[cfg(not(unix))]
	let ino = 0;
	Some(Fingerprint {
		mtime_secs,
		len,
		ino,
	})
}

/// The on-disk record of the last fingerprint the server successfully
/// applied per watched file. The CLI reads this to know whether the
/// running server has reloaded a write it just made, instead of
/// betting the server picks it up on its next two-second poll.
///
/// The file is `<data_dir>/reload.status` and contains a single JSON
/// object whose keys are the watched basenames and values are
/// fingerprints. A missing or empty file means the server has not
/// reloaded anything yet; the CLI treats that as "no server" and
/// returns at once.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReloadStatus {
	/// The fingerprints keyed by the file's basename (e.g.
	/// `accounts.toml`). An entry is `None` when the file was absent
	/// at the last poll.
	#[serde(flatten)]
	pub files: std::collections::BTreeMap<String, Option<Fingerprint>>,
}

impl ReloadStatus {
	/// Where the server publishes this status. Stable across releases
	/// so the CLI can be paired with a slightly older or newer server.
	pub const FILENAME: &'static str = "reload.status";

	/// True when `self` carries the same fingerprint for `name` as
	/// `target` (or both are absent). A reload that has not yet
	/// observed the just-written file returns false here.
	pub fn matches(&self, name: &str, target: Option<Fingerprint>) -> bool {
		self.files.get(name).copied().unwrap_or(None) == target
	}
}

/// The fingerprint of `path` as the file watcher would compute it
/// for the reload status: a stable three-field identity suitable for
/// the CLI to compare against the server's last applied version.
pub fn reload_fingerprint(path: &Path) -> Option<Fingerprint> {
	fingerprint(path)
}

impl FileWatcher {
	/// Where the reload status is written, relative to the data dir
	/// the watcher was built with.
	pub fn status_path(&self) -> PathBuf {
		self.data_dir.join(ReloadStatus::FILENAME)
	}

	/// Persist the current `last` map so a CLI can read it after a
	/// write. Atomic over the existing file: the watcher uses the
	/// same `write_secret` helper the dynamic stores use to avoid a
	/// half-written status file.
	fn write_status(&self) {
		let mut status = ReloadStatus::default();
		for watch in &self.watches {
			let fp = self.last.get(&watch.path).copied().flatten();
			status.files.insert(watch.kind.label().to_string(), fp);
		}
		let text = match serde_json::to_string_pretty(&status) {
			Ok(text) => text,
			Err(error) => {
				tracing::warn!(
					target: "epistle::directory_store::file_watcher",
					%error,
					"cannot serialise reload status; CLI will not see the latest fingerprint"
				);
				return;
			}
		};
		let path = self.status_path();
		if let Err(error) = crate::storage::write_secret(&path, text.as_bytes()) {
			tracing::warn!(
				target: "epistle::directory_store::file_watcher",
				path = %path.display(),
				%error,
				"cannot write reload status; CLI will not see the latest fingerprint"
			);
		}
	}
}

/// Read the reload status the server published under
/// `<data_dir>/reload.status`. Returns `None` when the file is
/// missing or unparseable: the CLI treats both as "no server has
/// reloaded anything yet" and returns at once.
pub fn read_reload_status(data_dir: &Path) -> Option<ReloadStatus> {
	let path = data_dir.join(ReloadStatus::FILENAME);
	let text = std::fs::read_to_string(&path).ok()?;
	serde_json::from_str(&text).ok()
}

/// Block (up to `timeout`) until the server's reload status carries
/// `target` for the file at `watched_path`, polled every
/// `interval`. Returns:
///
/// * `Ok(())` on a match (including the case where no server is
///   running and the status file is absent or empty).
/// * `Err(WaitError::Timeout)` when the timeout expires without a
///   match.
///
/// The function is intentionally blocking and `std::thread::sleep`-based
/// because the CLI is a short-lived process: an async runtime would
/// be more machinery than the work it does here. The
/// `interval` of 100 ms is short enough that the CLI does not extend
/// the worst-case end-to-end latency beyond a few hundred milliseconds
/// of the server's two-second poll, and long enough that the loop
/// does not pin a CPU core.
pub fn wait_for_reload(
	data_dir: &Path,
	watched_path: &Path,
	target: Option<Fingerprint>,
	timeout: std::time::Duration,
) -> Result<(), WaitError> {
	let Some(name) = watched_path.file_name().and_then(|n| n.to_str()) else {
		// A path with no filename component is the caller's bug;
		// the CLI never builds one. Treat as a no-match so the
		// caller times out cleanly.
		return Err(WaitError::NoFilename);
	};
	let start = std::time::Instant::now();
	let interval = std::time::Duration::from_millis(100);
	loop {
		match read_reload_status(data_dir) {
			None => return Ok(()),
			Some(status) => {
				if status.matches(name, target) {
					return Ok(());
				}
			}
		}
		if start.elapsed() >= timeout {
			return Err(WaitError::Timeout);
		}
		std::thread::sleep(interval);
	}
}

/// What `wait_for_reload` cannot do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
	/// The watched path has no filename component.
	NoFilename,
	/// The server's status did not catch up to the just-written
	/// fingerprint within the timeout.
	Timeout,
}

impl std::fmt::Display for WaitError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			WaitError::NoFilename => formatter.write_str("watched path has no filename"),
			WaitError::Timeout => formatter.write_str("timeout waiting for reload"),
		}
	}
}

impl std::error::Error for WaitError {}

#[cfg(test)]
#[path = "file_watcher_tests.rs"]
mod tests;
