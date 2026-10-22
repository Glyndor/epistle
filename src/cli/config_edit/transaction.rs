//! Prepare both service files before replacing either, with verified rollback.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::{ConfigDocument, Outcome, file};
use std::time::{Duration, SystemTime};

/// The prefix and suffix every staged copy carries, so a reader can tell a
/// staged candidate from an operator's file.
const STAGING: (&str, &str) = (".service.", ".tmp");

/// A staged copy older than this belongs to a command that died: a command
/// still running holds the configuration lock this sweep runs under, and its
/// own copies are younger than any plausible edit.
const ORPHAN_AGE: Duration = Duration::from_secs(3600);

/// A validated generated file, tied to the bytes used to render it.
pub(crate) struct Companion {
	pub(crate) path: PathBuf,
	pub(crate) original: Vec<u8>,
	pub(crate) candidate: Vec<u8>,
}

struct Staged(PathBuf, bool);

impl Drop for Staged {
	fn drop(&mut self) {
		if !self.1 {
			let _ = fs::remove_file(&self.0);
		}
	}
}

struct Replacement {
	path: PathBuf,
	original: Vec<u8>,
	metadata: Metadata,
	candidate: Staged,
	backup: Staged,
	replaced: bool,
}

fn read(path: &Path) -> Result<(Vec<u8>, Metadata), String> {
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let mut file = options.open(path).map_err(|e| e.to_string())?;
	let metadata = file.metadata().map_err(|e| e.to_string())?;
	if !metadata.is_file() {
		return Err(format!("{} must be a regular file", path.display()));
	}
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
	Ok((bytes, metadata))
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
	let staging = Staged(
		parent(path).join(format!(
			"{}{}{}",
			STAGING.0,
			uuid::Uuid::now_v7(),
			STAGING.1
		)),
		false,
	);
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
		let (current, metadata) = read(path)?;
		if current != original || expected.is_some_and(|old| !file::same_file(old, &metadata)) {
			return Err(format!(
				"{} changed while editing; retry the command",
				path.display()
			));
		}
		let candidate = stage(path, candidate, &metadata)?;
		let backup = stage(path, original, &metadata)?;
		sync_parent(path)?;
		Ok(Self {
			path: path.into(),
			original: original.into(),
			metadata,
			candidate,
			backup,
			replaced: false,
		})
	}

	fn apply(&mut self) -> Result<(), String> {
		let (current, metadata) = read(&self.path)?;
		if current != self.original || !file::same_file(&self.metadata, &metadata) {
			return Err(format!(
				"{} changed while editing; retry the command",
				self.path.display()
			));
		}
		fs::rename(&self.candidate.0, &self.path).map_err(|e| e.to_string())?;
		self.replaced = true;
		sync_parent(&self.path)
	}

	fn restore(&mut self) -> Result<(), String> {
		if !self.replaced {
			return Ok(());
		}
		let result = (|| {
			let restore = stage(&self.path, &self.original, &self.metadata)?;
			fs::rename(&restore.0, &self.path).map_err(|e| e.to_string())?;
			sync_parent(&self.path)?;
			let (bytes, metadata) = read(&self.path)?;
			if bytes != self.original || !same_permissions(&self.metadata, &metadata) {
				return Err("restored file verification failed".into());
			}
			Ok(())
		})();
		if result.is_err() {
			// The prepared backup remains durable even if the directory stops
			// accepting writes during rollback.
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

/// Remove the staged copies a killed command left in `dir` and name the ones
/// that went. A command that dies between its two renames can not restore
/// anything, so the copies stay until the next command finds them; without
/// this sweep they pile up one pair per death, and each holds a whole copy of
/// `mail.toml` or of the generated Compose file.
///
/// Only files this module stages are touched: the name has to carry the
/// staging prefix and suffix, and the copy has to be older than
/// [`ORPHAN_AGE`]. Anything else in the directory is the operator's.
pub(crate) fn sweep_orphans(dir: &Path) -> Vec<PathBuf> {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return Vec::new();
	};
	let now = SystemTime::now();
	let mut swept = Vec::new();
	for entry in entries.flatten() {
		let name = entry.file_name();
		let name = name.to_string_lossy();
		if !name.starts_with(STAGING.0) || !name.ends_with(STAGING.1) {
			continue;
		}
		let Ok(metadata) = entry.metadata() else {
			continue;
		};
		if !metadata.is_file() {
			continue;
		}
		if metadata
			.modified()
			.is_ok_and(|written| now.duration_since(written).unwrap_or_default() < ORPHAN_AGE)
		{
			continue;
		}
		if std::fs::remove_file(entry.path()).is_ok() {
			swept.push(entry.path());
		}
	}
	swept
}

/// Say on stderr which staged copies a sweep removed, so the operator hears
/// that a command died there instead of finding the files later.
pub(crate) fn announce_swept(swept: &[PathBuf]) {
	if swept.is_empty() {
		return;
	}
	let where_ = swept[0]
		.parent()
		.map(|dir| dir.display().to_string())
		.unwrap_or_default();
	crate::cli::style::warn(format!(
		"removed {} staged cop{} left by an interrupted command in {where_}: {}",
		swept.len(),
		if swept.len() == 1 { "y" } else { "ies" },
		swept
			.iter()
			.map(|path| path.display().to_string())
			.collect::<Vec<_>>()
			.join(", ")
	));
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
mod tests {
	use super::*;

	#[test]
	fn a_second_replacement_failure_restores_the_first_file_and_permissions() {
		let dir = tempfile::tempdir().unwrap();
		let a = dir.path().join("mail.toml");
		let b = dir.path().join("compose.yaml");
		crate::storage::write_secret(&a, b"original config").unwrap();
		crate::storage::write_secret(&b, b"original compose").unwrap();
		let before = fs::metadata(&a).unwrap();
		let mut first =
			Some(Replacement::prepare(&a, b"original config", b"new config", None).unwrap());
		let mut second =
			Some(Replacement::prepare(&b, b"original compose", b"new compose", None).unwrap());
		// Losing the second staged candidate forces a real rename failure
		// after the first replacement has completed.
		fs::remove_file(&second.as_ref().unwrap().candidate.0).unwrap();
		assert!(apply_pair(&mut first, &mut second).is_err());
		assert_eq!(fs::read(&a).unwrap(), b"original config");
		assert_eq!(fs::read(&b).unwrap(), b"original compose");
		assert!(same_permissions(&before, &fs::metadata(&a).unwrap()));
	}
	#[test]
	fn an_uncoordinated_compose_edit_is_preserved_and_the_config_is_restored() {
		let dir = tempfile::tempdir().unwrap();
		let a = dir.path().join("mail.toml");
		let b = dir.path().join("compose.yaml");
		crate::storage::write_secret(&a, b"config before").unwrap();
		crate::storage::write_secret(&b, b"compose before").unwrap();
		let mut first =
			Some(Replacement::prepare(&a, b"config before", b"config after", None).unwrap());
		let mut second =
			Some(Replacement::prepare(&b, b"compose before", b"compose after", None).unwrap());
		crate::storage::write_secret(&b, b"operator update").unwrap();
		assert!(apply_pair(&mut first, &mut second).is_err());
		assert_eq!(fs::read(&a).unwrap(), b"config before");
		assert_eq!(fs::read(&b).unwrap(), b"operator update");
	}

	#[test]
	fn a_failed_rollback_retains_a_durable_recovery_copy() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("mail.toml");
		crate::storage::write_secret(&path, b"config before").unwrap();
		let mut replacement =
			Replacement::prepare(&path, b"config before", b"config after", None).unwrap();
		replacement.apply().unwrap();
		fs::remove_file(&path).unwrap();
		fs::create_dir(&path).unwrap();
		let backup = replacement.backup.0.clone();
		let error = replacement.restore().unwrap_err();
		assert!(error.contains(&backup.display().to_string()));
		drop(replacement);
		assert!(
			backup.is_file(),
			"failed rollback must retain its recovery copy"
		);
		assert_eq!(fs::read(backup).unwrap(), b"config before");
	}
	#[test]
	fn simultaneous_rollback_failures_name_both_recovery_copies() {
		let dir = tempfile::tempdir().unwrap();
		let a = dir.path().join("mail.toml");
		let b = dir.path().join("compose.yaml");
		crate::storage::write_secret(&a, b"config before").unwrap();
		crate::storage::write_secret(&b, b"compose before").unwrap();
		let mut first =
			Some(Replacement::prepare(&a, b"config before", b"config after", None).unwrap());
		let mut second =
			Some(Replacement::prepare(&b, b"compose before", b"compose after", None).unwrap());
		first.as_mut().unwrap().apply().unwrap();
		second.as_mut().unwrap().apply().unwrap();
		for path in [&a, &b] {
			fs::remove_file(path).unwrap();
			fs::create_dir(path).unwrap();
		}
		let copies = [
			first.as_ref().unwrap().backup.0.clone(),
			second.as_ref().unwrap().backup.0.clone(),
		];
		let error = apply_pair(&mut first, &mut second).unwrap_err();
		for path in copies {
			assert!(error.contains(&path.display().to_string()), "{error}");
		}
	}

	/// A command killed between its two renames leaves its staged copies
	/// behind. The next command under the lock sweeps them, and only them:
	/// the operator's own files and the copy of a command still running stay.
	#[test]
	fn a_sweep_takes_the_staged_copies_of_a_dead_command_and_nothing_else() {
		let dir = tempfile::tempdir().unwrap();
		let old = dir
			.path()
			.join(format!(".service.{}.tmp", uuid::Uuid::now_v7()));
		let young = dir
			.path()
			.join(format!(".service.{}.tmp", uuid::Uuid::now_v7()));
		let foreign = dir.path().join("mail.toml");
		for path in [&old, &young, &foreign] {
			fs::write(path, b"copy of a config").unwrap();
		}
		age(&old);
		assert_eq!(sweep_orphans(dir.path()), vec![old.clone()]);
		assert!(!old.exists());
		assert!(
			young.is_file(),
			"a copy younger than an hour belongs to a command that still runs"
		);
		assert_eq!(fs::read(&foreign).unwrap(), b"copy of a config");
		assert!(
			sweep_orphans(&dir.path().join("absent")).is_empty(),
			"a directory that is not there has nothing to sweep"
		);
	}

	/// Backdate a staged copy so the sweep takes it as an orphan.
	fn age(path: &Path) {
		let when = SystemTime::now() - ORPHAN_AGE - Duration::from_secs(60);
		fs::File::options()
			.write(true)
			.open(path)
			.unwrap()
			.set_times(fs::FileTimes::new().set_modified(when))
			.unwrap();
	}
}
