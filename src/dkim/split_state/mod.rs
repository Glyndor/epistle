//! What `epistle dkim split` has done, kept between its runs.
//!
//! `<data_dir>/dkim-split.json` holds, for every domain that was moved to a
//! key of its own:
//!
//! - when its entry was written (`written`);
//! - when the server was restarted onto it (`restarted`), which is the moment
//!   the old key stops signing for the domain and the only one the overlap
//!   before the old key's records are retired can count from. A domain
//!   written and not restarted is *pending*: the split repeats the restart,
//!   and `--finish` retires nothing for it;
//! - the shared key's selectors, with the public keys they were published
//!   with (`stale`), as they were when the domain moved. A later rotation
//!   retires its own records and key files; this keeps the names and the keys
//!   needed to recognise what is left, which would otherwise be forgotten.
//!
//! A file that exists and does not parse is an error, never an empty state.
//! A lock file beside it keeps two runs from interleaving.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name inside the data directory.
pub const FILE: &str = "dkim-split.json";

/// Lock file name inside the data directory.
const LOCK: &str = "dkim-split.lock";

/// A selector the shared key was published under, and its public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleSelector {
	/// The selector.
	pub selector: String,
	/// The `p=` values the shared key published under it.
	pub expected: Vec<String>,
}

/// One moved domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moved {
	/// Epoch second the domain's entry was written.
	pub written: u64,
	/// Epoch second the server was restarted onto the new key, once it was.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub restarted: Option<u64>,
	/// The shared key's selectors at the time, to retire.
	#[serde(default)]
	pub stale: Vec<StaleSelector>,
}

fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(FILE)
}

/// Every moved domain, empty when nothing was recorded.
pub fn read(data_dir: &Path) -> Result<BTreeMap<String, Moved>, String> {
	let bytes = match std::fs::read(path(data_dir)) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
		Err(error) => return Err(format!("cannot read {FILE}: {error}")),
	};
	serde_json::from_slice(&bytes).map_err(|error| format!("cannot parse {FILE}: {error}"))
}

fn write(data_dir: &Path, all: &BTreeMap<String, Moved>) -> Result<(), String> {
	let bytes = serde_json::to_vec_pretty(all).map_err(|error| error.to_string())?;
	crate::storage::write_secret(&path(data_dir), &bytes)
		.map_err(|error| format!("cannot write {FILE}: {error}"))
}

/// Record that `domain`'s entry was written at `now`, with the shared key's
/// selectors it leaves behind.
///
/// A domain whose earlier write was never confirmed by a restart keeps that
/// write's time: this is the retry of an interrupted run. A domain that was
/// already restarted onto an earlier key is a new move: its time is `now` and
/// its restart is cleared, so the confirmation of the old key can never pass
/// for the new one. The shared key's selectors from every write are kept.
pub fn record_written(
	data_dir: &Path,
	domain: &str,
	now: u64,
	stale: Vec<StaleSelector>,
) -> Result<(), String> {
	let mut all = read(data_dir)?;
	let moved = all.entry(domain.to_ascii_lowercase()).or_insert(Moved {
		written: now,
		restarted: None,
		stale: Vec::new(),
	});
	if moved.restarted.is_some() {
		moved.written = now;
		moved.restarted = None;
	}
	for add in stale {
		match moved.stale.iter_mut().find(|s| s.selector == add.selector) {
			Some(known) => {
				for p in add.expected {
					if !known.expected.contains(&p) {
						known.expected.push(p);
					}
				}
			}
			None => moved.stale.push(add),
		}
	}
	write(data_dir, &all)
}

/// The domains written and not yet restarted onto. Only domains `hosted`
/// accepts count (those that have a `[[dkim.domain]]` entry in the loaded
/// configuration): a record of a move whose entry never reached the file is
/// not a restart to wait for.
pub fn pending(data_dir: &Path, hosted: impl Fn(&str) -> bool) -> Result<Vec<String>, String> {
	Ok(read(data_dir)?
		.into_iter()
		.filter(|(domain, moved)| moved.restarted.is_none() && hosted(domain))
		.map(|(domain, _)| domain)
		.collect())
}

/// Record that the server was restarted onto the key of every pending domain
/// `hosted` accepts, at `now`; returns the domains it settled. A record with
/// no entry behind it is never sealed as restarted.
pub fn mark_restarted(
	data_dir: &Path,
	now: u64,
	hosted: impl Fn(&str) -> bool,
) -> Result<Vec<String>, String> {
	let mut all = read(data_dir)?;
	let mut settled = Vec::new();
	for (domain, moved) in &mut all {
		if moved.restarted.is_none() && hosted(domain) {
			moved.restarted = Some(now);
			settled.push(domain.clone());
		}
	}
	if !settled.is_empty() {
		write(data_dir, &all)?;
	}
	Ok(settled)
}

/// Take the lock that keeps two `dkim split` runs on one data directory from
/// interleaving. It is held until the returned file is dropped, waits up to
/// `within`, and says so when it gives up.
pub fn lock(data_dir: &Path, within: std::time::Duration) -> Result<std::fs::File, String> {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::OpenOptionsExt;
	let lock_path = data_dir.join(LOCK);
	let file = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.truncate(false)
		.mode(0o600)
		.open(&lock_path)
		.map_err(|error| format!("cannot open {}: {error}", lock_path.display()))?;
	let began = std::time::Instant::now();
	loop {
		// SAFETY: flock on a descriptor this function owns.
		let taken = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
		if taken {
			return Ok(file);
		}
		if began.elapsed() >= within {
			return Err(format!(
				"another dkim split is running on this data directory ({} is locked)",
				lock_path.display()
			));
		}
		std::thread::sleep(std::time::Duration::from_millis(100));
	}
}

#[cfg(test)]
mod tests;
