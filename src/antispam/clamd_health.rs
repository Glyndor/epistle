//! A small on-disk record of clamd scans that failed, so `epistle status`
//! can say that mail has been accepted unscanned (or deferred, under
//! `clamd_on_error = "defer"`). The server writes it; the status check, a
//! separate process, reads it.
//!
//! The record is advisory. A write that fails is logged at debug and
//! dropped: it must never hold up mail, whose fate is already decided at
//! that point.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// File under the data directory that holds the record.
pub(crate) const FILE: &str = "clamd-health.json";

/// What the record says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Health {
	/// Scans that failed open since the last one that succeeded.
	#[serde(default)]
	pub(crate) failures: u64,
	/// Epoch seconds of the first failure of the current run of failures.
	#[serde(default)]
	pub(crate) failing_since: Option<u64>,
	/// Epoch seconds of the most recent failure.
	#[serde(default)]
	pub(crate) last_failure: Option<u64>,
	/// Epoch seconds of the first success after the last run of failures.
	#[serde(default)]
	pub(crate) recovered_at: Option<u64>,
}

/// Read the record under `data_dir`; `None` when there is none or it does
/// not parse.
pub(crate) fn read(data_dir: &Path) -> Option<Health> {
	let bytes = std::fs::read(data_dir.join(FILE)).ok()?;
	serde_json::from_slice(&bytes).ok()
}

/// The writer the scanner holds.
#[derive(Debug)]
pub(crate) struct HealthFile {
	data_dir: PathBuf,
	/// Whether a failure may be on record. Starts set, so the first success
	/// of a run clears whatever an earlier run left behind.
	maybe_failing: AtomicBool,
	/// Serializes read-modify-write cycles between concurrent scans.
	lock: Mutex<()>,
}

impl HealthFile {
	pub(crate) fn new(data_dir: &Path) -> Self {
		HealthFile {
			data_dir: data_dir.to_path_buf(),
			maybe_failing: AtomicBool::new(true),
			lock: Mutex::new(()),
		}
	}

	/// Count one scan that failed open.
	pub(crate) fn failed(&self) {
		self.maybe_failing.store(true, Ordering::Relaxed);
		let now = now();
		self.update(|health| {
			health.failures = health.failures.saturating_add(1);
			health.failing_since.get_or_insert(now);
			health.last_failure = Some(now);
			true
		});
	}

	/// Note a scan that worked. Writes only when failures are on record, so
	/// the common case costs one atomic load.
	pub(crate) fn succeeded(&self) {
		if !self.maybe_failing.swap(false, Ordering::Relaxed) {
			return;
		}
		let now = now();
		self.update(|health| {
			if health.failures == 0 {
				return false;
			}
			health.failures = 0;
			health.failing_since = None;
			health.recovered_at = Some(now);
			true
		});
	}

	/// Apply `change` to the record and write it back when it says so.
	fn update(&self, change: impl FnOnce(&mut Health) -> bool) {
		let Ok(_guard) = self.lock.lock() else {
			return;
		};
		let mut health = read(&self.data_dir).unwrap_or_default();
		if !change(&mut health) {
			return;
		}
		if let Err(error) = self.write(&health) {
			tracing::debug!(%error, "cannot record the clamd scan state");
		}
	}

	/// Write through a temporary file and a rename, so a reader never sees
	/// half a record.
	fn write(&self, health: &Health) -> std::io::Result<()> {
		let bytes = serde_json::to_vec(health).map_err(std::io::Error::other)?;
		let tmp = self.data_dir.join(format!("{FILE}.tmp"));
		std::fs::write(&tmp, bytes)?;
		std::fs::rename(&tmp, self.data_dir.join(FILE))
	}
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0)
}

#[cfg(test)]
#[path = "clamd_health_tests.rs"]
mod tests;
