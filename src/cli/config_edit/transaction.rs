//! Prepare both service files before replacing either, with verified rollback.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use super::sweep::is_recovery;
use super::{ConfigDocument, Outcome, file};

/// A validated generated file, tied to the bytes used to render it.
pub(crate) struct Companion {
	pub(crate) path: PathBuf,
	pub(crate) original: Vec<u8>,
	pub(crate) candidate: Vec<u8>,
}

/// A file this transaction put next to the one it protects: the candidate a
/// rename installs, or the backup it keeps of the original. The flag says
/// whether the file outlives the transaction. A candidate goes with it once
/// both renames are done; a backup stays, because it is the only original
/// left when a rollback fails.
struct Staged(PathBuf, bool);

impl Drop for Staged {
	fn drop(&mut self) {
		if !self.1 {
			let _ = fs::remove_file(&self.0);
		}
	}
}

struct Replacement {
	/// The path the operator knows, which is where a diagnostic names the file.
	path: PathBuf,
	/// The file the rename replaces: the path itself, or the file a symlink at
	/// that path points at. The staged copies live in its own directory, so the
	/// rename stays inside one filesystem and the link survives.
	target: PathBuf,
	original: Vec<u8>,
	metadata: Metadata,
	candidate: Staged,
	backup: Staged,
	replaced: bool,
}

/// What one opening of a service file gives: its bytes and the metadata of
/// the file behind them. When the path is a symlink the file is read through
/// it, and the write replaces the link itself with a regular file: the
/// destination is never named by a path that could change between the read
/// and the rename.
struct Opened {
	bytes: Vec<u8>,
	metadata: Metadata,
}

/// `compose.yaml` is often a symlink into another directory of the
/// installation, so the link is followed. The shared reader opens once, never
/// waits for a fifo, and takes the bytes and the metadata from that one
/// descriptor, so a path swapped between the check and the read does not
/// decide what is staged.
fn read(path: &Path) -> Result<Opened, String> {
	use crate::cli::regular_read::{is_not_regular, read_with_metadata};
	let (bytes, metadata) = read_with_metadata(path).map_err(|error| {
		if is_not_regular(&error) {
			format!("{} must be a regular file", path.display())
		} else {
			error.to_string()
		}
	})?;
	Ok(Opened { bytes, metadata })
}

fn parent(path: &Path) -> &Path {
	path.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(Path::new("."))
}

fn sync_parent(path: &Path) -> Result<(), String> {
	File::open(parent(path))
		.and_then(|dir| dir.sync_all())
		.map_err(|e| e.to_string())
}

fn stage(path: &Path, bytes: &[u8], metadata: &Metadata) -> Result<Staged, String> {
	write_copy(super::sweep::staged_path(parent(path)), bytes, metadata)
}

/// The original, written under the recovery name from the start. A rollback
/// that can not put the file back has to leave a copy the operator still finds
/// a day later, so the name the sweep holds for a week cannot depend on a
/// rename that the same failure may refuse: whatever breaks the rollback
/// breaks the rename too, and a staged name is one the sweep takes after an
/// hour.
fn backup(path: &Path, bytes: &[u8], metadata: &Metadata) -> Result<Staged, String> {
	write_copy(super::sweep::recovery_path(parent(path)), bytes, metadata)
}

fn write_copy(name: PathBuf, bytes: &[u8], metadata: &Metadata) -> Result<Staged, String> {
	let staging = Staged(name, false);
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut file = options.open(&staging.0).map_err(|e| e.to_string())?;
	file.write_all(bytes).map_err(|e| e.to_string())?;
	file::preserve_owner(&file, metadata).map_err(|e| e.to_string())?;
	file.set_permissions(metadata.permissions())
		.map_err(|e| e.to_string())?;
	file.sync_all().map_err(|e| e.to_string())?;
	Ok(staging)
}

impl Replacement {
	fn prepare(
		path: &Path,
		original: &[u8],
		candidate: &[u8],
		expected: Option<&Metadata>,
	) -> Result<Self, String> {
		let opened = read(path)?;
		if opened.bytes != original
			|| expected.is_some_and(|old| !file::same_file(old, &opened.metadata))
		{
			return Err(format!(
				"{} changed while editing; retry the command",
				path.display()
			));
		}
		let target: PathBuf = path.into();
		let candidate = stage(&target, candidate, &opened.metadata)?;
		let backup = backup(&target, original, &opened.metadata)?;
		sync_parent(&target)?;
		Ok(Self {
			path: path.into(),
			target,
			original: original.into(),
			metadata: opened.metadata,
			candidate,
			backup,
			replaced: false,
		})
	}

	fn apply(&mut self) -> Result<(), String> {
		let opened = read(&self.path)?;
		if opened.bytes != self.original || !file::same_file(&self.metadata, &opened.metadata) {
			return Err(format!(
				"{} changed while editing; retry the command",
				self.path.display()
			));
		}
		fs::rename(&self.candidate.0, &self.target).map_err(|e| e.to_string())?;
		self.replaced = true;
		sync_parent(&self.target)
	}

	fn restore(&mut self) -> Result<(), String> {
		if !self.replaced {
			return Ok(());
		}
		let result = (|| {
			let restore = stage(&self.target, &self.original, &self.metadata)?;
			fs::rename(&restore.0, &self.target).map_err(|e| e.to_string())?;
			sync_parent(&self.target)?;
			let opened = read(&self.path)?;
			if opened.bytes != self.original || !same_permissions(&self.metadata, &opened.metadata)
			{
				return Err("restored file verification failed".into());
			}
			Ok(())
		})();
		if result.is_err() {
			// The backup already carries the name the sweep keeps for a week,
			// so the file this error names is the one the operator still finds
			// when they read it, and there is no rename left that the failure
			// could also break.
			self.backup.1 = true;
			return Err(format!(
				"rollback failed for {}; recovery copy: {}",
				self.path.display(),
				self.backup.0.display()
			));
		}
		result
	}
}

fn same_permissions(a: &Metadata, b: &Metadata) -> bool {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		a.mode() == b.mode() && a.uid() == b.uid() && a.gid() == b.gid()
	}
	#[cfg(not(unix))]
	{
		a.permissions().readonly() == b.permissions().readonly()
	}
}

/// Validate and stage both candidates before any replacement. Callers hold
/// the common configuration lock through this operation and the reload.
pub(crate) fn commit_pair(
	document: ConfigDocument,
	companion: Option<Companion>,
) -> Result<Outcome, String> {
	document.config()?;
	let (current, metadata) = file::read(&document.path)?;
	if current != document.original || !file::same_file(&document.metadata, &metadata) {
		return Err("config changed while editing; retry the command".into());
	}
	let rendered = document.render();
	let mut first = if rendered == document.original {
		None
	} else {
		Some(Replacement::prepare(
			&document.path,
			document.original.as_bytes(),
			rendered.as_bytes(),
			Some(&document.metadata),
		)?)
	};
	let mut second = companion
		.map(|other| Replacement::prepare(&other.path, &other.original, &other.candidate, None))
		.transpose()?;
	apply_pair(&mut first, &mut second)
}

fn apply_pair(
	first: &mut Option<Replacement>,
	second: &mut Option<Replacement>,
) -> Result<Outcome, String> {
	let result = (|| {
		if let Some(first) = first {
			first.apply()?;
		}
		if let Some(second) = second {
			second.apply()?;
		}
		Ok(())
	})();
	if let Err(error) = result {
		let second_restore = second.as_mut().map(Replacement::restore).transpose();
		let first_restore = first.as_mut().map(Replacement::restore).transpose();
		let failures: Vec<String> = [second_restore, first_restore]
			.into_iter()
			.filter_map(Result::err)
			.collect();
		return Err(if failures.is_empty() {
			error
		} else {
			format!("{error}; {}", failures.join("; "))
		});
	}
	Ok(if first.is_some() || second.is_some() {
		Outcome::Changed
	} else {
		Outcome::Unchanged
	})
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;
