//! Verified reads and durable replacement of the same configuration path.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(super) fn read(path: &Path) -> Result<(String, Metadata), String> {
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let mut file = options
		.open(path)
		.map_err(|error| format!("cannot open {}: {error}", path.display()))?;
	let metadata = file.metadata().map_err(|error| error.to_string())?;
	if !metadata.is_file() {
		return Err("config must be a regular file".into());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mode = metadata.permissions().mode() & 0o777;
		if mode & 0o077 != 0 {
			return Err(crate::config::ConfigError::InsecurePermissions {
				path: path.into(),
				mode,
				kind: "config file",
			}
			.to_string());
		}
	}
	let mut text = String::new();
	file.read_to_string(&mut text)
		.map_err(|error| error.to_string())?;
	Ok((text, metadata))
}

struct Staging(PathBuf);

impl Drop for Staging {
	fn drop(&mut self) {
		let _ = fs::remove_file(&self.0);
	}
}

pub(super) fn replace(
	path: &Path,
	original: &str,
	metadata: &Metadata,
	text: &str,
) -> Result<(), String> {
	let parent = path
		.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(Path::new("."));
	let staging_path = parent.join(format!(".mail.toml.{}.tmp", uuid::Uuid::now_v7()));
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut file = options
		.open(&staging_path)
		.map_err(|error| error.to_string())?;
	let staging = Staging(staging_path);
	file.write_all(text.as_bytes())
		.map_err(|error| error.to_string())?;
	preserve_owner(&file, metadata).map_err(|error| error.to_string())?;
	file.set_permissions(metadata.permissions())
		.map_err(|error| error.to_string())?;
	file.sync_all().map_err(|error| error.to_string())?;
	let (current, current_metadata) = read(path)?;
	if current != original || !same_file(metadata, &current_metadata) {
		return Err("config changed while editing; retry the command".into());
	}
	fs::rename(&staging.0, path).map_err(|error| error.to_string())?;
	File::open(parent)
		.and_then(|dir| dir.sync_all())
		.map_err(|error| error.to_string())
}

#[cfg(unix)]
fn preserve_owner(file: &File, metadata: &Metadata) -> std::io::Result<()> {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::MetadataExt;
	let current = file.metadata()?;
	if current.uid() == metadata.uid() && current.gid() == metadata.gid() {
		return Ok(());
	}
	// SAFETY: the descriptor is live and the IDs come from the verified file.
	if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } == -1 {
		return Err(std::io::Error::last_os_error());
	}
	Ok(())
}

#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
	use std::os::unix::fs::MetadataExt;
	a.dev() == b.dev()
		&& a.ino() == b.ino()
		&& a.mode() == b.mode()
		&& a.uid() == b.uid()
		&& a.gid() == b.gid()
}

#[cfg(not(unix))]
fn preserve_owner(_file: &File, _metadata: &Metadata) -> std::io::Result<()> {
	Ok(())
}

#[cfg(not(unix))]
fn same_file(_a: &Metadata, _b: &Metadata) -> bool {
	true
}
