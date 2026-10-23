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
	let mut file = options.open(path).map_err(|error| {
		// O_NOFOLLOW turns a symlink into ELOOP, whose wording differs
		// between libcs; name the actual problem instead.
		#[cfg(unix)]
		if error.raw_os_error() == Some(libc::ELOOP) {
			return format!(
				"{} is a symlink; point --config at the file itself",
				path.display()
			);
		}
		format!("cannot open {}: {error}", path.display())
	})?;
	let metadata = file.metadata().map_err(|error| error.to_string())?;
	if !metadata.is_file() {
		return Err("config must be a regular file".into());
	}
	owner_only(path, &metadata)?;
	let mut text = String::new();
	file.read_to_string(&mut text)
		.map_err(|error| error.to_string())?;
	Ok((text, metadata))
}

/// The bytes of a configuration path that may be a symlink, read without
/// waiting. `mail.toml` is routinely a link into another directory of the
/// installation and the loader has always followed it, so this follows it
/// too, while [`read`] refuses it because the caller is about to replace the
/// file at the path. The open carries `O_NONBLOCK` and the file is refused
/// unless the descriptor says it is regular, so a fifo at the path or behind
/// the link can not turn a command that holds the common lock into a wait on
/// a writer that never arrives. The permission rule and the wording of an
/// I/O failure are the ones `Config::load` applies, so a path this reader
/// takes is one the loader would have taken too.
pub(crate) fn read_through_link(path: &Path) -> Result<String, String> {
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NONBLOCK);
	}
	let mut file = options
		.open(path)
		.map_err(|source| unreadable(path, source))?;
	let metadata = file.metadata().map_err(|source| unreadable(path, source))?;
	if !metadata.is_file() {
		return Err(format!("{} must be a regular file", path.display()));
	}
	owner_only(path, &metadata)?;
	let mut text = String::new();
	file.read_to_string(&mut text)
		.map_err(|source| unreadable(path, source))?;
	Ok(text)
}

/// Refuse a configuration file other users can reach. The mode is taken from
/// the descriptor that was read, so a path swapped after the open does not
/// decide what was checked.
fn owner_only(path: &Path, metadata: &Metadata) -> Result<(), String> {
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
	#[cfg(not(unix))]
	let _ = (path, metadata);
	Ok(())
}

/// An I/O failure at `path`, in the loader's own words: the operator reads
/// the same message whether the read came from here or from `Config::load`.
fn unreadable(path: &Path, source: std::io::Error) -> String {
	crate::config::ConfigError::Read {
		path: path.to_path_buf(),
		source,
		kind: "config file",
	}
	.to_string()
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
pub(super) fn preserve_owner(file: &File, metadata: &Metadata) -> std::io::Result<()> {
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
pub(super) fn same_file(a: &Metadata, b: &Metadata) -> bool {
	use std::os::unix::fs::MetadataExt;
	a.dev() == b.dev()
		&& a.ino() == b.ino()
		&& a.mode() == b.mode()
		&& a.uid() == b.uid()
		&& a.gid() == b.gid()
}

#[cfg(not(unix))]
pub(super) fn preserve_owner(_file: &File, _metadata: &Metadata) -> std::io::Result<()> {
	Ok(())
}

#[cfg(not(unix))]
pub(super) fn same_file(_a: &Metadata, _b: &Metadata) -> bool {
	true
}
