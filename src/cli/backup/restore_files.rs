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
	// Private-key material is always `0600` on restore, regardless of what
	// the archive claimed. A tar built with a permissive umask (or by an
	// attacker who edited the header) must not bring a key back group- or
	// world-readable.
	let mode = enforced_mode_for(relative, mode & 0o777);
	let result = (|| {
		file.write_all(content)?;
		file.set_permissions(std::fs::Permissions::from_mode(mode))?;
		validate_destination(data_dir, relative)?;
		std::fs::rename(&temp, &dest)
	})();
	// Remove the temporary file on errors; a successful rename already consumed it.
	let _ = std::fs::remove_file(&temp);
	result
}

/// The permission bits to write to `relative` on restore. Private-key material
/// is tightened to `0600`; ordinary files keep the mode the archive recorded
/// (already masked to the bottom 9 bits by the caller). `relative` is the
/// path inside `data_dir`, with `data/` and `./` stripped by [`relative_path`].
pub(super) fn enforced_mode_for(relative: &Path, archived_mode: u32) -> u32 {
	if is_private_key_path(relative) {
		0o600
	} else {
		archived_mode
	}
}

/// True for paths that carry private-key material and so must always land at
/// `0600` on restore, regardless of what the archive's mode field records.
///
/// The list is intentionally narrow: a tar created by an operator who chmod'd
/// the live tree should round-trip the operator's intent on every other file.
/// Only files whose contents are by definition secret (signing keys,
/// per-server pseudonyms, account credential stores) get the hard floor. New
/// key-shaped additions should land here too rather than rely on the archive
/// author getting the mode right by hand.
pub(super) fn is_private_key_path(relative: &Path) -> bool {
	let path_str = relative.to_string_lossy();
	// Exact filenames: anything that sits at the data_dir root and is a known
	// server-wide key. The match is by tail so `accounts/<name>/key` (if such
	// a path is ever added) does not collide.
	if path_str == "log-pseudonym.key" || path_str.ends_with("/log-pseudonym.key") {
		return true;
	}
	// Any file ending in `.key` is private by convention: DKIM selectors
	// (`dkim-edNN.key`), the storage at-rest key, the TLS private key, and
	// so on. PEM private keys live in `.pem` (TLS/ACME/ARC), also secret.
	let last = relative
		.file_name()
		.map(|s| s.to_string_lossy().into_owned())
		.unwrap_or_default();
	if last.ends_with(".key") || last.ends_with(".pem") {
		return true;
	}
	// Account stores hold TOTP seeds and credentials and so are secret too,
	// and the per-account secret-bearing files live under `accounts/<name>/`.
	if path_str.starts_with("accounts/") && (last.ends_with(".toml") || last.ends_with(".json")) {
		return true;
	}
	false
}

#[cfg(test)]
mod tests {
	use std::os::unix::fs::PermissionsExt;

	use super::{is_private_key_path, lay_files};

	#[test]
	fn private_key_classifier_recognises_known_shapes() {
		use std::path::Path;
		let sensitive = [
			"log-pseudonym.key",
			"accounts/alice/log-pseudonym.key", // tail match, not collide
			"dkim-ed20240101.key",
			"accounts/alice/totp.toml",
			"accounts/bob/credentials.json",
			"tls/key.pem",
			"acme/account.pem",
		];
		for path in sensitive {
			assert!(
				is_private_key_path(Path::new(path)),
				"{path} must be classified as private"
			);
		}
	}

	#[test]
	fn private_key_classifier_leaves_ordinary_files_alone() {
		use std::path::Path;
		let ordinary = [
			"accounts/alice/new/0001.eml",
			"accounts/alice/folders/Projects..2024",
			"dkim-rotation.json",
			"server.crt",
			"envelope.json",
		];
		for path in ordinary {
			assert!(
				!is_private_key_path(Path::new(path)),
				"{path} must NOT be classified as private"
			);
		}
	}

	/// Restore a tarball-like list whose `key` archive entry is recorded as
	/// 0644 and confirm the restored file lands at 0600. Without the
	/// private-key floor this would land at 0644 and a backup that captured
	/// a permissive umask (or was tampered with) would silently re-introduce
	/// a world-readable key.
	#[test]
	fn lay_files_forces_0600_on_archived_private_key() {
		let data_dir = tempfile::tempdir().expect("tempdir");
		let entries = vec![
			// Sensitive entry, recorded in the tar as 0644.
			(
				"data/dkim-ed20240101.key".to_string(),
				0o644_u32,
				b"FAKE-PEM-PRIVATE".to_vec(),
			),
			// Ordinary entry, recorded in the tar as 0644.
			(
				"data/accounts/alice/new/0001.eml".to_string(),
				0o644_u32,
				b"Subject: hi\r\n\r\nbody".to_vec(),
			),
		];
		lay_files(&entries, data_dir.path()).expect("lay_files");

		let key_path = data_dir.path().join("dkim-ed20240101.key");
		let key_mode = std::fs::metadata(&key_path)
			.expect("key metadata")
			.permissions()
			.mode();
		assert_eq!(
			key_mode & 0o777,
			0o600,
			"archived private key landed at {:o}, must be 0600",
			key_mode & 0o777
		);

		let ordinary_path = data_dir.path().join("accounts/alice/new/0001.eml");
		let ordinary_mode = std::fs::metadata(&ordinary_path)
			.expect("ordinary metadata")
			.permissions()
			.mode();
		assert_eq!(
			ordinary_mode & 0o777,
			0o644,
			"ordinary file should keep the archive's mode, got {:o}",
			ordinary_mode & 0o777
		);
	}
}
