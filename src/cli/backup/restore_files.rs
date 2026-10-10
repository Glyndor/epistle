//! Validate archive paths before replacing files under the data directory.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn lay_files(entries: &[(String, u32, Vec<u8>)], data_dir: &Path) -> io::Result<()> {
	// Preflight the entire archive so a later invalid entry cannot leave a partial restore.
	let paths = entries
		.iter()
		.map(|(name, _, _)| {
			let relative = relative_path(name)?;
			validate_destination(data_dir, relative)?;
			Ok(relative)
		})
		.collect::<io::Result<Vec<_>>>()?;
	for ((_, mode, content), relative) in entries.iter().zip(paths) {
		write_file(data_dir, relative, *mode, content)?;
	}
	Ok(())
}

fn relative_path(name: &str) -> io::Result<&Path> {
	if name == super::DATABASE_SQL_NAME {
		return Ok(Path::new(name));
	}
	let relative = name
		.strip_prefix("data/")
		.ok_or_else(|| io::Error::other("unsupported archive entry name"))?;
	// Path::components normalizes repeated separators and interior dots; reject them first.
	if relative
		.split('/')
		.any(|part| part.is_empty() || part == ".")
		|| Path::new(relative)
			.components()
			.any(|component| !matches!(component, Component::Normal(_)))
	{
		return Err(io::Error::other(
			"archive entry path is not a normal relative path",
		));
	}
	Ok(Path::new(relative))
}

fn refuse_symlink(path: &Path) -> io::Result<()> {
	match std::fs::symlink_metadata(path) {
		Ok(metadata) if metadata.is_symlink() => {
			Err(io::Error::other("restore path contains a symlink"))
		}
		Ok(_) => Ok(()),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error),
	}
}

fn validate_destination(data_dir: &Path, relative: &Path) -> io::Result<()> {
	refuse_symlink(data_dir)?;
	let mut path = data_dir.to_path_buf();
	for component in relative.components() {
		path.push(component);
		refuse_symlink(&path)?;
	}
	Ok(())
}

fn create_temp(parent: &Path) -> io::Result<(File, PathBuf)> {
	static NEXT: AtomicU64 = AtomicU64::new(0);
	for _ in 0..128 {
		let id = NEXT.fetch_add(1, Ordering::Relaxed);
		let path = parent.join(format!(".epistle-restore-{}-{id}", std::process::id()));
		match OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW)
			.open(&path)
		{
			Ok(file) => return Ok((file, path)),
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
			Err(error) => return Err(error),
		}
	}
	Err(io::Error::new(
		io::ErrorKind::AlreadyExists,
		"restore temporary names are occupied",
	))
}

fn write_file(data_dir: &Path, relative: &Path, mode: u32, content: &[u8]) -> io::Result<()> {
	let dest = data_dir.join(relative);
	let parent = dest
		.parent()
		.ok_or_else(|| io::Error::other("missing restore parent"))?;
	validate_destination(data_dir, relative)?;
	std::fs::create_dir_all(parent)?;
	validate_destination(data_dir, relative)?;
	let (mut file, temp) = create_temp(parent)?;
	let result = (|| {
		file.write_all(content)?;
		file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
		validate_destination(data_dir, relative)?;
		std::fs::rename(&temp, &dest)
	})();
	// Remove the temporary file on errors; a successful rename already consumed it.
	let _ = std::fs::remove_file(&temp);
	result
}
