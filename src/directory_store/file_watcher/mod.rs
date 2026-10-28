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
use crate::directory_store::reload_status::{self, ReloadStatus};

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

/// Hot-reload target for `warmup.json`, the operator's IP warm-up
/// settings (see [`crate::queue::warmup`]). Held as a trait object for
/// the same reason as [`ApiKeyReloader`].
pub trait WarmupReloader: Send + Sync {
	/// Read the settings file again and apply its new orders. The
	/// implementor reads the file itself, so it can refuse one that is not
	/// a private file of the server's user; a refusal leaves the running
	/// settings untouched.
	fn reload_warmup(&self) -> std::io::Result<()>;
}

/// The reloaders the watcher feeds besides the account store.
#[derive(Clone, Copy, Default)]
struct Targets<'a> {
	api_keys: Option<&'a dyn ApiKeyReloader>,
	warmup: Option<&'a dyn WarmupReloader>,
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
	Warmup,
}

impl ReloadKind {
	fn label(self) -> &'static str {
		match self {
			ReloadKind::Accounts => "accounts.toml",
			ReloadKind::AppPasswords => "app_passwords.toml",
			ReloadKind::Masked => "masked.json",
			ReloadKind::Aliases => "aliases.json",
			ReloadKind::ApiKeys => "api_keys.toml",
			ReloadKind::Warmup => crate::queue::warmup::settings::SETTINGS_FILE,
		}
	}

	/// Apply `text` to `store` and rebuild the directory. Mirrors the
	/// `persist` + `replace(build_directory())` pair the in-server
	/// mutators run, minus the persist step (the bytes already live on
	/// disk under us).
	fn apply(
		self,
		store: &AccountStore,
		targets: Targets<'_>,
		text: &str,
	) -> Result<(), StoreError> {
		match self {
			ReloadKind::Accounts => store.reload_accounts_from(text),
			ReloadKind::AppPasswords => store.reload_app_passwords_from(text),
			ReloadKind::Masked => store.reload_masked_from(text),
			ReloadKind::Aliases => store.reload_aliases_from(text),
			ReloadKind::Warmup => match targets.warmup {
				Some(reloader) => reloader
					.reload_warmup()
					.map_err(|error| StoreError::Invalid(error.to_string())),
				None => Ok(()),
			},
			ReloadKind::ApiKeys => match targets.api_keys {
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
		targets: Targets<'_>,
		path: &Path,
	) -> Result<bool, StoreError> {
		match std::fs::read_to_string(path) {
			Ok(text) => {
				self.apply(store, targets, &text)?;
				Ok(true)
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				self.apply(store, targets, "")?;
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
	/// Optional hot-reload target for `warmup.json`.
	warmup: Option<Arc<dyn WarmupReloader>>,
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
	/// The `warmup.json` warm-up settings.
	Warmup,
}

impl From<ReloadKind> for PollTarget {
	fn from(kind: ReloadKind) -> Self {
		match kind {
			ReloadKind::Accounts => PollTarget::Accounts,
			ReloadKind::AppPasswords => PollTarget::AppPasswords,
			ReloadKind::Masked => PollTarget::Masked,
			ReloadKind::Aliases => PollTarget::Aliases,
			ReloadKind::ApiKeys => PollTarget::ApiKeys,
			ReloadKind::Warmup => PollTarget::Warmup,
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
			Watch {
				path: data_dir.join(ReloadKind::Warmup.label()),
				kind: ReloadKind::Warmup,
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
			warmup: None,
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

	/// Attach the reloader for `warmup.json`, before [`spawn`](Self::spawn).
	pub fn with_warmup(mut self, reloader: Arc<dyn WarmupReloader>) -> Self {
		self.warmup = Some(reloader);
		self
	}

	/// The reloaders to feed.
	fn targets(&self) -> Targets<'_> {
		Targets {
			api_keys: self.api_keys.as_deref(),
			warmup: self.warmup.as_deref(),
		}
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
		// One status write per poll that loaded something, and a bare
		// mtime update on every other poll, so the CLI sees both what
		// is loaded and that the server is still polling.
		if report
			.events
			.iter()
			.any(|event| matches!(event, PollEvent::Loaded(_)))
		{
			self.write_status();
		} else {
			self.refresh_status();
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
				match watch.kind.apply(&self.store, self.targets(), &text) {
					Ok(()) => {
						self.last.insert(watch.path.clone(), Some(now));
						self.last_warned.insert(watch.path.clone(), None);
						tracing::info!(
							target: "epistle::directory_store::file_watcher",
							file = watch.kind.label(),
							"reloaded dynamic-store file",
						);
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
					.apply_from_disk(&self.store, self.targets(), &watch.path)
				{
					Ok(_) => {
						self.last.insert(watch.path.clone(), None);
						self.last_warned.insert(watch.path.clone(), None);
						tracing::info!(
							target: "epistle::directory_store::file_watcher",
							file = watch.kind.label(),
							"reloaded dynamic-store file (now absent)",
						);
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
		// Publish what the server loaded at startup before the first
		// poll, so a CLI write in the first interval has a status to
		// wait on instead of reading the server as absent.
		self.write_status();
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

/// The fingerprint of `path` as the file watcher computes it, for the
/// CLI to compare against the server's reload status.
pub fn reload_fingerprint(path: &Path) -> Option<Fingerprint> {
	fingerprint(path)
}

impl FileWatcher {
	/// Where the reload status is written, under the data dir the
	/// watcher was built with.
	pub fn status_path(&self) -> PathBuf {
		reload_status::status_path(&self.data_dir)
	}

	/// Publish the fingerprints the server has loaded, so a CLI that
	/// just wrote one of the files can tell when the change is live.
	fn write_status(&self) {
		let mut status = ReloadStatus::default();
		for watch in &self.watches {
			let loaded = self.last.get(&watch.path).copied().flatten();
			status.files.insert(watch.kind.label().to_string(), loaded);
		}
		let path = self.status_path();
		if let Err(error) = reload_status::write(&path, &status) {
			tracing::warn!(
				target: "epistle::directory_store::file_watcher",
				%error,
				"cannot write the reload status; the CLI will not wait for this server's reloads",
			);
		}
	}

	/// Move the status file's mtime forward so the CLI can tell this
	/// server is still polling. Falls back to a full write when the
	/// cheap update fails: the file was removed, or it belongs to
	/// another user because it was written before a privilege drop.
	fn refresh_status(&self) {
		if reload_status::touch(&self.status_path()).is_err() {
			self.write_status();
		}
	}
}

#[cfg(test)]
mod tests;
