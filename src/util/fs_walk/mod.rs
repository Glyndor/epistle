//! Directory walks that exclude links and special files from mail data.
//!
//! Every walk and read is in [`rooted`], every write, lock, rename and removal
//! in [`rooted_write`]: the caller names the trusted root the path lies
//! under, and nothing outside it is reached.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{DirEntry, FileType, ReadDir};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) mod rooted;
pub(crate) mod rooted_write;

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
	let notice = skipped_notice(path);
	if tracing::enabled!(tracing::Level::WARN) {
		tracing::warn!("{notice}");
	} else {
		eprintln!("warning: {notice}");
	}
}

/// The warning text for a skipped path.
fn skipped_notice(path: &Path) -> String {
	format!(
		"skipping non-regular data path {}",
		crate::log_id::path(path)
	)
}

pub(crate) fn allowed(path: &Path, kind: FileType) -> bool {
	if kind.is_file() || kind.is_dir() {
		true
	} else {
		warn_skipped(path);
		false
	}
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

#[cfg(test)]
mod tests;
