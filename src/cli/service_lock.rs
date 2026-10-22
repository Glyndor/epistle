//! One lock for service edits, init reruns and stack configuration writers.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Lock the configuration directory before reading either service file.
/// The sibling stays in place when mail.toml is atomically replaced.
pub(super) fn acquire(config: &Path) -> Result<File, String> {
	let parent = config
		.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(Path::new("."));
	let path = parent.join(".epistle-config.lock");
	let file = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.truncate(false)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
		.open(&path)
		.map_err(|e| format!("cannot lock {}: {e}", path.display()))?;
	let metadata = file.metadata().map_err(|e| e.to_string())?;
	if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
		return Err(format!(
			"{} must be an owner-only regular lock file",
			path.display()
		));
	}
	crate::storage::lock::flock_exclusive_blocking(file.as_raw_fd()).map_err(|e| e.to_string())?;
	Ok(file)
}
