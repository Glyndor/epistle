//! The reload status the running server publishes for the CLI.
//!
//! The file watcher writes `<data_dir>/reload.status` once when it
//! starts and again after every change it applies: a JSON object that
//! maps each watched basename to the fingerprint the server last
//! loaded. Every poll in between moves the file's mtime forward
//! without rewriting it, so the mtime says a server is still polling.
//!
//! The CLI reads both halves. It waits until the fingerprint of the
//! file it just wrote shows up in the status, and it returns at once
//! when the status file is missing or its mtime is older than
//! [`LIVENESS_WINDOW`]: a server that stopped or crashed leaves
//! nothing behind to wait for.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::file_watcher::Fingerprint;

/// How often the server's file watcher polls the dynamic-store files.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How old the status file's mtime may be before the CLI concludes
/// that no server is refreshing it. Five poll intervals leave room for
/// a poll that a slow reload delayed, while a stopped server stops
/// costing the CLI a wait shortly after it went away.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(POLL_INTERVAL.as_secs() * 5);

/// How often the CLI rereads the status while it waits.
const WAIT_STEP: Duration = Duration::from_millis(100);

/// The fingerprint the server last loaded for each watched file.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReloadStatus {
	/// The fingerprints keyed by the file's basename (e.g.
	/// `accounts.toml`). An entry is `None` when the file was absent
	/// at the last poll.
	#[serde(flatten)]
	pub files: BTreeMap<String, Option<Fingerprint>>,
}

impl ReloadStatus {
	/// Where the server publishes this status, under its data dir.
	/// Stable across releases so a CLI can be paired with a slightly
	/// older or newer server.
	pub const FILENAME: &'static str = "reload.status";

	/// True when `self` carries the same fingerprint for `name` as
	/// `target` (or both are absent).
	pub fn matches(&self, name: &str, target: Option<Fingerprint>) -> bool {
		self.files.get(name).copied().unwrap_or(None) == target
	}
}

/// The status file under `data_dir`.
pub fn status_path(data_dir: &Path) -> PathBuf {
	data_dir.join(ReloadStatus::FILENAME)
}

/// Read the status under `data_dir`. `None` when the file is missing,
/// unreadable or unparseable; the CLI treats all three as "no server
/// to wait for".
pub fn read_reload_status(data_dir: &Path) -> Option<ReloadStatus> {
	let text = std::fs::read_to_string(status_path(data_dir)).ok()?;
	serde_json::from_str(&text).ok()
}

/// True when the status file under `data_dir` exists and its mtime
/// moved within [`LIVENESS_WINDOW`] of `now`. An mtime ahead of `now`
/// counts as live: the clocks disagree, the file is not old.
pub fn server_is_live(data_dir: &Path, now: SystemTime) -> bool {
	let Ok(modified) = std::fs::metadata(status_path(data_dir)).and_then(|meta| meta.modified())
	else {
		return false;
	};
	match now.duration_since(modified) {
		Ok(age) => age <= LIVENESS_WINDOW,
		Err(_) => true,
	}
}

/// Write `status` to `path` atomically, so a reader never sees half a
/// file.
pub(super) fn write(path: &Path, status: &ReloadStatus) -> std::io::Result<()> {
	let text = serde_json::to_string_pretty(status).map_err(std::io::Error::other)?;
	crate::storage::write_secret(path, text.as_bytes())
}

/// Move the mtime of the status file at `path` to now. A metadata
/// update only: the content is not rewritten and nothing is synced,
/// which keeps the every-poll heartbeat cheap.
pub(super) fn touch(path: &Path) -> std::io::Result<()> {
	std::fs::File::options()
		.write(true)
		.open(path)?
		.set_modified(SystemTime::now())
}

/// Remove the status under `data_dir` when the server stops, so the
/// CLI does not read a stopped server as a live one. A missing file is
/// already the wanted state.
pub fn remove_reload_status(data_dir: &Path) {
	let path = status_path(data_dir);
	match std::fs::remove_file(&path) {
		Ok(()) => {}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
		Err(error) => tracing::warn!(
			target: "epistle::directory_store::file_watcher",
			%error,
			"cannot remove the reload status; the CLI stops waiting on it once it goes stale",
		),
	}
}

/// How [`wait_for_reload`] ended without a timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadWait {
	/// The server's status carries the fingerprint the caller waited for.
	Loaded,
	/// No server is polling: the status file is missing, unreadable or
	/// stale.
	NoServer,
}

/// Block, up to `timeout`, until the status under `data_dir` carries
/// `target` for the file at `watched_path`. Returns at once when no
/// server is polling. Blocking with `std::thread::sleep` is deliberate:
/// the CLI is a short-lived process and an async runtime would be more
/// machinery than this loop.
pub fn wait_for_reload(
	data_dir: &Path,
	watched_path: &Path,
	target: Option<Fingerprint>,
	timeout: Duration,
) -> Result<ReloadWait, WaitError> {
	let Some(name) = watched_path.file_name().and_then(|n| n.to_str()) else {
		return Err(WaitError::NoFilename);
	};
	let start = Instant::now();
	loop {
		if !server_is_live(data_dir, SystemTime::now()) {
			return Ok(ReloadWait::NoServer);
		}
		match read_reload_status(data_dir) {
			None => return Ok(ReloadWait::NoServer),
			Some(status) if status.matches(name, target) => return Ok(ReloadWait::Loaded),
			Some(_) => {}
		}
		let elapsed = start.elapsed();
		if elapsed >= timeout {
			return Err(WaitError::Timeout);
		}
		std::thread::sleep(WAIT_STEP.min(timeout - elapsed));
	}
}

/// What [`wait_for_reload`] cannot do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
	/// The watched path has no filename component.
	NoFilename,
	/// The server's status did not catch up to the fingerprint within
	/// the timeout.
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
