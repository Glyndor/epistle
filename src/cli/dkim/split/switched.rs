//! When each domain was switched to its own key.
//!
//! The overlap window for retiring the shared key's records runs from the
//! moment `dkim split` wrote the domain's entry, not from the age of a file:
//! a key can be made days before the switch, or copied with an old date. The
//! moment is kept in `<data_dir>/dkim-split.json`, one epoch second per
//! domain, and a domain with no moment recorded is refused, not assumed old.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// File name inside the data directory.
pub(super) const FILE: &str = "dkim-split.json";

fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(FILE)
}

/// The recorded moments, empty when nothing was recorded. A file that exists
/// and does not parse is an error: it is never read as "no domain switched".
pub(super) fn read(data_dir: &Path) -> Result<BTreeMap<String, u64>, String> {
	let bytes = match std::fs::read(path(data_dir)) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
		Err(error) => return Err(format!("cannot read {FILE}: {error}")),
	};
	serde_json::from_slice(&bytes).map_err(|error| format!("cannot parse {FILE}: {error}"))
}

/// Record that `domains` were switched at `now`, keeping what was recorded.
pub(super) fn record(data_dir: &Path, domains: &[String], now: u64) -> Result<(), String> {
	let mut all = read(data_dir)?;
	for domain in domains {
		all.insert(domain.to_ascii_lowercase(), now);
	}
	let bytes = serde_json::to_vec_pretty(&all).map_err(|error| error.to_string())?;
	crate::storage::write_secret(&path(data_dir), &bytes)
		.map_err(|error| format!("cannot write {FILE}: {error}"))
}
