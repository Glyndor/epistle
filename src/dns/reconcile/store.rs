//! Where the ledgers live, and the lock that keeps two publishers apart.
//!
//! One ledger per zone under `<data_dir>/dns-publish/<zone>.json`, next to
//! the journal `dns lockdown` keeps. `epistle dns publish` and the server's
//! reconcile loop write the same files, so both take the lock in that
//! directory before they read a zone.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::Ledger;
use crate::dns::names::{canonical_name, is_valid_name};

/// The directory of the ledgers.
pub fn dir(data_dir: &Path) -> PathBuf {
	data_dir.join("dns-publish")
}

/// The ledger file of `zone`. A zone that is not a valid DNS name has no
/// file: it would otherwise name a path outside the directory.
pub fn path(data_dir: &Path, zone: &str) -> Result<PathBuf, String> {
	let zone = canonical_name(zone);
	if !is_valid_name(&zone) || zone.starts_with('*') {
		return Err(format!(
			"{zone} is not a zone name a ledger can be kept for"
		));
	}
	Ok(dir(data_dir).join(format!("{zone}.json")))
}

/// The ledger of `zone`, empty when there is none. A ledger that cannot be
/// read stops the caller: going on would overwrite it and lose what epistle
/// published, and every record in it would turn foreign.
pub fn load(data_dir: &Path, zone: &str) -> Result<Ledger, String> {
	let path = path(data_dir, zone)?;
	let text = match std::fs::read_to_string(&path) {
		Ok(text) => text,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return Ok(Ledger::new(canonical_name(zone)));
		}
		Err(error) => {
			return Err(format!(
				"cannot read the ledger {}: {error}",
				path.display()
			));
		}
	};
	let ledger: Ledger = serde_json::from_str(&text).map_err(|error| {
		format!(
			"the ledger {} is not readable ({error}); move it aside to start over",
			path.display()
		)
	})?;
	if canonical_name(&ledger.zone) != canonical_name(zone) {
		return Err(format!(
			"the ledger {} is for {}, not {zone}",
			path.display(),
			ledger.zone
		));
	}
	Ok(ledger)
}

/// Store `ledger` through a temporary file and a rename, so a crash never
/// leaves half a ledger.
pub fn store(data_dir: &Path, ledger: &Ledger) -> Result<(), String> {
	let path = path(data_dir, &ledger.zone)?;
	let parent = dir(data_dir);
	std::fs::create_dir_all(&parent)
		.map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
	let text = serde_json::to_string_pretty(ledger)
		.map_err(|error| format!("cannot encode the ledger: {error}"))?;
	let staging = path.with_extension("json.new");
	std::fs::write(&staging, text)
		.and_then(|()| std::fs::rename(&staging, &path))
		.map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The zones that have a ledger, sorted. No directory is no ledger.
pub fn zones(data_dir: &Path) -> Result<Vec<String>, String> {
	let dir = dir(data_dir);
	let entries = match std::fs::read_dir(&dir) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(error) => return Err(format!("cannot read {}: {error}", dir.display())),
	};
	let mut zones = Vec::new();
	for entry in entries {
		let entry = entry.map_err(|error| format!("cannot read {}: {error}", dir.display()))?;
		let name = entry.file_name().to_string_lossy().into_owned();
		if let Some(zone) = name.strip_suffix(".json")
			&& is_valid_name(zone)
		{
			zones.push(zone.to_string());
		}
	}
	zones.sort();
	Ok(zones)
}

/// The lock of the ledger directory. Held while it lives.
#[derive(Debug)]
pub struct Lock {
	_file: File,
}

/// Take the lock, waiting at most `wait` for whoever holds it. `None` when
/// it is still held after the wait: the caller does not publish.
pub fn lock(data_dir: &Path, wait: Duration) -> Result<Option<Lock>, String> {
	let dir = dir(data_dir);
	std::fs::create_dir_all(&dir)
		.map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
	let path = dir.join(".lock");
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(&path)
		.map_err(|error| format!("cannot open {}: {error}", path.display()))?;
	let began = Instant::now();
	loop {
		match file.try_lock() {
			Ok(()) => return Ok(Some(Lock { _file: file })),
			Err(std::fs::TryLockError::WouldBlock) if began.elapsed() < wait => {
				std::thread::sleep(Duration::from_millis(100));
			}
			Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
			Err(std::fs::TryLockError::Error(error)) => {
				return Err(format!("cannot lock {}: {error}", path.display()));
			}
		}
	}
}
