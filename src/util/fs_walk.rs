//! Directory walks that exclude links and special files from mail data.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{DirEntry, FileType, ReadDir};
use std::io;
use std::path::{Path, PathBuf};

thread_local! {
	static WARNED: RefCell<Option<HashSet<PathBuf>>> = const { RefCell::new(None) };
}

pub(crate) struct WarningScope(bool);

// Group nested walks so metadata probes and sidecar reads warn once per path.
pub(crate) fn warning_scope() -> WarningScope {
	WarningScope(WARNED.with(|warned| {
		let mut warned = warned.borrow_mut();
		if warned.is_some() {
			false
		} else {
			*warned = Some(HashSet::new());
			true
		}
	}))
}

impl Drop for WarningScope {
	fn drop(&mut self) {
		if self.0 {
			WARNED.with(|warned| *warned.borrow_mut() = None);
		}
	}
}

pub(crate) fn warn_skipped(path: &Path) {
	let repeated = WARNED.with(|warned| {
		warned
			.borrow_mut()
			.as_mut()
			.is_some_and(|seen| !seen.insert(path.to_path_buf()))
	});
	if repeated {
		return;
	}
	if tracing::enabled!(tracing::Level::WARN) {
		tracing::warn!("skipping non-regular data path {}", path.display());
	} else {
		eprintln!("warning: skipping non-regular data path {}", path.display());
	}
}

pub(crate) fn allowed(path: &Path, kind: FileType) -> bool {
	if kind.is_file() || kind.is_dir() {
		true
	} else {
		warn_skipped(path);
		false
	}
}

// Known directory names also need checking: an accounts/new/folders link must
// not bypass entry filtering simply because the caller joins its name directly.
pub(crate) fn check_directories(path: &Path) -> io::Result<()> {
	for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
		match std::fs::symlink_metadata(ancestor) {
			Ok(metadata) if metadata.is_dir() => {}
			Ok(_) => {
				warn_skipped(ancestor);
				return Err(io::Error::new(
					io::ErrorKind::NotFound,
					"skipped non-directory data path",
				));
			}
			Err(error) if error.kind() == io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
	}
	Ok(())
}

pub(crate) fn read_dir(path: impl AsRef<Path>) -> io::Result<Entries> {
	check_directories(path.as_ref())?;
	Ok(Entries(std::fs::read_dir(path)?))
}

pub(crate) struct Entries(ReadDir);

impl Iterator for Entries {
	type Item = io::Result<DirEntry>;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let entry = match self.0.next()? {
				Ok(entry) => entry,
				Err(error) => return Some(Err(error)),
			};
			match entry.file_type() {
				Ok(kind) if kind.is_file() || kind.is_dir() => return Some(Ok(entry)),
				Ok(_) => {
					warn_skipped(&entry.path());
				}
				Err(error) => return Some(Err(error)),
			}
		}
	}
}

pub(crate) fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
	use std::io::Read;
	let path = path.as_ref();
	if let Some(parent) = path.parent() {
		check_directories(parent)?;
	}
	if !std::fs::symlink_metadata(path)?.is_file() {
		warn_skipped(path);
		return Err(io::Error::new(
			io::ErrorKind::NotFound,
			"skipped non-regular data file",
		));
	}
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		// A replaced leaf must not follow a link or block on a FIFO after the check.
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let mut file = options.open(path)?;
	if !file.metadata()?.is_file() {
		warn_skipped(path);
		return Err(io::Error::new(
			io::ErrorKind::NotFound,
			"skipped non-regular data file",
		));
	}
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	Ok(bytes)
}

pub(crate) fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
	String::from_utf8(read(path)?)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
