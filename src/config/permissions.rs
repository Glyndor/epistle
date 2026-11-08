//! The permission rule the configuration file must satisfy before it is read.

use std::path::Path;

use super::ConfigError;

/// Reject a file that is readable or writable by group or others: it may hold
/// secrets, so it must be owner-only. `kind` labels the message the operator
/// will read in the refusal (`"config file"` for the loader, `"[database]
/// password_file"` for the database secret). Best effort on non-Unix platforms
/// where the bit check is meaningless and the check passes through.
#[cfg(unix)]
pub(super) fn check_permissions(path: &Path, kind: &'static str) -> Result<(), ConfigError> {
	use std::os::unix::fs::PermissionsExt;
	let mode = std::fs::metadata(path)
		.map_err(|source| ConfigError::Read {
			path: path.to_path_buf(),
			source,
			kind: "config file",
		})?
		.permissions()
		.mode();
	if mode & 0o077 != 0 {
		return Err(ConfigError::InsecurePermissions {
			path: path.to_path_buf(),
			mode: mode & 0o777,
			kind,
		});
	}
	Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), ConfigError> {
	Ok(())
}
