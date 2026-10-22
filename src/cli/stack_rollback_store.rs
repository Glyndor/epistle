//! Open rollback executables through an administrator-owned directory hierarchy.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

pub(super) struct Store {
	dir: File,
}

impl Store {
	pub(super) fn open(path: &Path) -> io::Result<Self> {
		if !path.is_absolute() {
			return Err(io::Error::other("rollback store must be absolute"));
		}
		let mut dir = File::open("/")?;
		check_directory(&dir, false)?;
		for component in path.components() {
			match component {
				Component::RootDir => continue,
				Component::Normal(name) => {
					dir = open_at(&dir, name.as_bytes(), libc::O_DIRECTORY)?;
					check_directory(&dir, false)?;
				}
				_ => return Err(io::Error::other("invalid rollback store path")),
			}
		}
		check_directory(&dir, true)?;
		Ok(Self { dir })
	}

	pub(super) fn select(&self, current: &str, to: Option<&str>) -> Result<(String, File), String> {
		let entries = std::fs::read_dir(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))
			.map_err(|error| error.to_string())?;
		let names: Vec<_> = entries
			.filter_map(|entry| entry.ok()?.file_name().into_string().ok())
			.collect();
		let chosen = super::pick(&names, current, to)?;
		let file = self
			.binary(&chosen)
			.map_err(|error| format!("{chosen}: {error}"))?;
		Ok((chosen, file))
	}

	/// The binary of one published generation, read from the directory the
	/// preinst renamed into place once the pair was complete and checked.
	fn binary(&self, name: &str) -> io::Result<File> {
		let generation = open_at(&self.dir, name.as_bytes(), libc::O_DIRECTORY)?;
		check_directory(&generation, true)?;
		let mut binary = checked_file(&generation, "epistle")?;
		let mut manifest = String::new();
		checked_file(&generation, "epistle.sha256")?
			.take(66)
			.read_to_string(&mut manifest)?;
		verify_digest(&mut binary, &manifest)?;
		Ok(binary)
	}
}

fn check_directory(dir: &File, private: bool) -> io::Result<()> {
	let metadata = dir.metadata()?;
	if !protected_directory(
		metadata.is_dir(),
		metadata.uid(),
		metadata.gid(),
		metadata.mode(),
		private,
	) {
		return Err(io::Error::other(
			"rollback directory must be root-owned and protected from other writers; the store must have mode 0700",
		));
	}
	Ok(())
}

fn checked_file(dir: &File, name: &str) -> io::Result<File> {
	let file = open_at(dir, name.as_bytes(), libc::O_NONBLOCK)?;
	let metadata = file.metadata()?;
	if !protected(metadata.is_file(), metadata.uid(), metadata.mode()) {
		return Err(io::Error::other(
			"rollback source must be a regular root-owned file without group or other write permission",
		));
	}
	Ok(file)
}

/// Apply the same root ownership and write restrictions to source descriptors and parents.
fn protected(expected_type: bool, uid: u32, mode: u32) -> bool {
	expected_type && uid == 0 && mode & 0o022 == 0
}

fn protected_directory(is_dir: bool, uid: u32, gid: u32, mode: u32, private: bool) -> bool {
	protected(is_dir, uid, mode) && gid == 0 && (!private || mode & 0o777 == 0o700)
}

fn open_at(dir: &File, name: &[u8], flags: i32) -> io::Result<File> {
	if name.contains(&b'/') || name == b"." || name == b".." {
		return Err(io::Error::other("invalid rollback entry name"));
	}
	let name = CString::new(name).map_err(|_| io::Error::other("invalid rollback entry name"))?;
	// SAFETY: dir stays open and name is a valid C string throughout the call.
	let fd = unsafe {
		libc::openat(
			dir.as_raw_fd(),
			name.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	// SAFETY: openat returned a new descriptor owned only by this File.
	Ok(unsafe { File::from_raw_fd(fd) })
}

fn verify_digest(binary: &mut File, manifest: &str) -> io::Result<()> {
	let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
	let mut buffer = [0u8; 64 * 1024];
	loop {
		let count = binary.read(&mut buffer)?;
		if count == 0 {
			break;
		}
		digest.update(&buffer[..count]);
	}
	let actual: String = digest
		.finish()
		.as_ref()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	if manifest.len() != 65 || manifest.strip_suffix('\n') != Some(actual.as_str()) {
		return Err(io::Error::other("rollback SHA-256 digest does not match"));
	}
	binary.rewind()
}

/// Install from the already verified descriptor, never reopening its pathname.
pub(super) fn install(binary: &mut File, installed: &Path) -> io::Result<()> {
	let parent = installed
		.parent()
		.ok_or_else(|| io::Error::other("missing binary directory"))?;
	let staged = parent.join(format!(".epistle-rollback-{:032x}", rand::random::<u128>()));
	let mut output = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&staged)?;
	let result = (|| {
		io::copy(binary, &mut output)?;
		output.set_permissions(std::fs::Permissions::from_mode(0o755))?;
		output.sync_all()?;
		std::fs::rename(&staged, installed)
	})();
	if result.is_err() {
		let _ = std::fs::remove_file(&staged);
	}
	result
}

#[cfg(test)]
#[path = "stack_rollback_store_tests.rs"]
mod tests;
