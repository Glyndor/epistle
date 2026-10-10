//! Keep writable mail mounts separate from the host account runtime.

use super::Invalid;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn check(data_dir: &Path) -> Result<(), Invalid> {
	if !data_dir.is_absolute() {
		return Ok(());
	}
	let home =
		current_home().map_err(|error| Invalid::DataDirHomeUnavailable(error.to_string()))?;
	let data = resolved(data_dir);
	let home_path = resolved(&home);
	let host_runtime = [".local/share/containers", ".config/systemd"]
		.iter()
		.any(|marker| std::fs::symlink_metadata(data.join(marker)).is_ok());
	if home_path.starts_with(&data) || host_runtime {
		return Err(Invalid::DataDirUnsafe {
			suggested: home.join("data").display().to_string(),
		});
	}
	Ok(())
}

// Resolve existing prefixes even when the final directory has not been created.
fn resolved(path: &Path) -> PathBuf {
	for prefix in path.ancestors() {
		if let Ok(real) = prefix.canonicalize()
			&& let Ok(tail) = path.strip_prefix(prefix)
		{
			let candidate = real.join(tail);
			return super::answers_validate::lexically_normalised(&candidate).unwrap_or(candidate);
		}
	}
	super::answers_validate::lexically_normalised(path).unwrap_or_else(|()| path.to_path_buf())
}

#[cfg(unix)]
fn current_home() -> io::Result<PathBuf> {
	use std::ffi::{CStr, OsStr};
	use std::os::unix::ffi::OsStrExt;
	let mut buffer = vec![0 as libc::c_char; 1024];
	loop {
		// SAFETY: a zeroed passwd is valid output storage for getpwuid_r.
		let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
		let mut result = std::ptr::null_mut();
		// SAFETY: output storage outlives the call and result is checked before use.
		let rc = unsafe {
			libc::getpwuid_r(
				libc::geteuid(),
				&mut passwd,
				buffer.as_mut_ptr(),
				buffer.len(),
				&mut result,
			)
		};
		if rc == libc::ERANGE && buffer.len() < 1 << 20 {
			buffer.resize(buffer.len() * 2, 0);
			continue;
		}
		if rc != 0 {
			return Err(io::Error::from_raw_os_error(rc));
		}
		if result.is_null() {
			return Err(io::Error::other("the current uid has no passwd entry"));
		}
		// SAFETY: successful getpwuid_r supplies a NUL-terminated home within buffer.
		let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
		return Ok(PathBuf::from(OsStr::from_bytes(home.to_bytes())));
	}
}

#[cfg(not(unix))]
fn current_home() -> io::Result<PathBuf> {
	std::env::var_os("USERPROFILE")
		.map(PathBuf::from)
		.ok_or_else(|| io::Error::other("USERPROFILE is not set"))
}
