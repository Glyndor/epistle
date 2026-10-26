//! Validate archive paths before replacing files under the data directory.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::util::path_component::StateFile;

/// Check every file entry of the archive against `data_dir` without writing
/// anything, so a restore can learn that it cannot lay the files down before
/// it changes the database.
pub(super) fn check_files(entries: &[(String, u32, Vec<u8>)], data_dir: &Path) -> io::Result<()> {
	checked_paths(entries, data_dir).map(drop)
}

fn checked_paths<'a>(
	entries: &'a [(String, u32, Vec<u8>)],
	data_dir: &Path,
) -> io::Result<Vec<&'a Path>> {
	entries
		.iter()
		.filter_map(|(name, _, _)| {
			// `database.sql` is the database dump; it goes to the
			// database restore step, not to `data_dir`. Laying it down
			// under `data_dir/database.sql` would make the next backup
			// carry it again, expose it to anything that walks the
			// data directory, and is not how the archive describes it
			// (it lives at the archive root, not under the `data/`
			// prefix that everything else uses). Skip the entry here;
			// `run_restore` extracts the SQL bytes from the same
			// `entries` slice and hands them straight to the database
			// restore step.
			if !lays_down(name) {
				return None;
			}
			match relative_path(name) {
				Ok(relative) => match validate_destination(data_dir, relative) {
					Ok(()) => Some(Ok(relative)),
					Err(error) => Some(Err(error)),
				},
				Err(error) => Some(Err(error)),
			}
		})
		.collect::<io::Result<Vec<_>>>()
}

pub(super) fn lay_files(entries: &[(String, u32, Vec<u8>)], data_dir: &Path) -> io::Result<()> {
	// Preflight the entire archive so a later invalid entry cannot leave a partial restore.
	let paths = checked_paths(entries, data_dir)?;
	for ((_, mode, content), relative) in entries
		.iter()
		.filter(|(name, _, _)| lays_down(name))
		.zip(paths)
	{
		write_file(data_dir, relative, *mode, content)?;
		if relative.file_name() == Some(OsStr::new(StateFile::JmapJournal.name())) {
			forget_jmap_epoch(data_dir, relative)?;
		}
	}
	Ok(())
}

/// Whether an archive entry is written under `data_dir`. `database.sql` goes
/// to the database restore step instead. A JMAP journal header is never
/// restored: the restored journal is older than what clients may hold, and
/// without its header the next JMAP request starts a new epoch, so every
/// client resyncs once instead of trusting positions that were rewound.
fn lays_down(name: &str) -> bool {
	name != super::DATABASE_SQL_NAME
		&& Path::new(name).file_name() != Some(OsStr::new(StateFile::JmapState.name()))
}

/// Drop the journal header next to a restored journal, which `--force` may
/// have left from the data directory being overwritten.
fn forget_jmap_epoch(data_dir: &Path, journal: &Path) -> io::Result<()> {
	let header = data_dir
		.join(journal)
		.with_file_name(StateFile::JmapState.name());
	match std::fs::remove_file(header) {
		Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
		_ => Ok(()),
	}
}

fn relative_path(name: &str) -> io::Result<&Path> {
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
	// If the restore target didn't exist yet, `create_dir_all` below will
	// make it under the host umask (typically 022), landing at 0755. Pin
	// `data_dir` itself to 0700 only when restore was the one that made
	// it: an operator's data_dir keeps its mode.
	let data_dir_pre_existed = data_dir.exists();
	std::fs::create_dir_all(parent)?;
	if !data_dir_pre_existed {
		std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
	}
	// Tighten every directory from `data_dir` down to the leaf parent to
	// `0700`, regardless of the host umask. `create_dir_all` walks the
	// chain and only creates what is missing, so an existing `secrets/`
	// left over from a lax tar build must also be locked down here.
	tighten_dir_chain(data_dir, parent)?;
	validate_destination(data_dir, relative)?;
	let (mut file, temp) = create_temp(parent)?;
	// Secret material is always `0600` on restore, regardless of what the
	// archive claimed. A tar built with a permissive umask (or by an
	// attacker who edited the header) must not bring a credential back
	// group- or world-readable.
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

/// Walk from the leaf `parent` up to (but not including) `data_dir` and
/// re-apply `0700` on every directory it touches. `data_dir` itself is left
/// alone by this helper; the call site tightens it only when restore was the
/// one that created it (see [`write_file`]). `set_permissions` is not affected
/// by the umask, so the result holds whatever mask the host runs with.
fn tighten_dir_chain(data_dir: &Path, parent: &Path) -> io::Result<()> {
	let mut current = parent;
	while current != data_dir {
		std::fs::set_permissions(current, std::fs::Permissions::from_mode(0o700))?;
		match current.parent() {
			Some(next) if next.starts_with(data_dir) => current = next,
			_ => break,
		}
	}
	Ok(())
}

/// The permission bits to write to `relative` on restore. Secret material is
/// tightened to `0600`; root-level operator config (`config.toml`) keeps the
/// owner bits the archive recorded but with any group or other bits stripped,
/// so a permissive umask on the source host cannot bring the live config back
/// group- or world-readable; ordinary files keep the mode the archive
/// recorded (already masked to the bottom 9 bits by the caller). `relative`
/// is the path inside `data_dir`, with `data/` and `./` stripped by
/// [`relative_path`].
pub(super) fn enforced_mode_for(relative: &Path, archived_mode: u32) -> u32 {
	if is_private_key_path(relative) {
		0o600
	} else if is_root_config_path(relative) {
		// Owner bits preserved, group and other dropped. An executable
		// archive entry still lands as `0700`; a `0644` archive lands as
		// `0600`; nothing reaches `data_dir` with another user able to read.
		archived_mode & 0o700
	} else {
		archived_mode
	}
}

/// True for `config.toml` at the root of `data_dir`. The live server reads
/// this file with each request, so it is the one config file the operator
/// cares about being unmodifiable from the outside; everything under
/// `secrets/`, `accounts/`, or named `accounts.toml` is handled by
/// [`is_private_key_path`] instead.
pub(super) fn is_root_config_path(relative: &Path) -> bool {
	relative.to_string_lossy() == "config.toml"
}

/// True for paths that carry credential material and so must always land at
/// `0600` on restore, regardless of what the archive's mode field records.
///
/// The rule is "credential store or key, everything else round-trips". A
/// public certificate or a message body is not secret and the operator
/// chmod'd it deliberately, so the archive mode is honoured there. Anything
/// whose content is secret by definition gets the hard floor:
/// signing keys, per-server pseudonyms, the global account store, and the
/// whole `secrets/` tree. New key-shaped additions should land here too
/// rather than rely on the archive author getting the mode right by hand.
pub(super) fn is_private_key_path(relative: &Path) -> bool {
	let path_str = relative.to_string_lossy();
	// Exact filenames: anything that sits at the data_dir root and is a known
	// server-wide key. The match is by tail so `accounts/<name>/key` (if such
	// a path is ever added) does not collide.
	if path_str == "log-pseudonym.key" || path_str.ends_with("/log-pseudonym.key") {
		return true;
	}
	// The global account store holds every account's credentials, not just the
	// ones living under `accounts/`, so the root file needs the floor too.
	if path_str == "accounts.toml" {
		return true;
	}
	// Anything under `secrets/` is a credential by where it is stored: the
	// database password, the at-rest storage key, per-feature API tokens.
	if path_str.starts_with("secrets/") {
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
#[path = "restore_files_tests_a4_modes.rs"]
mod tests_a4_modes;

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

	/// A restored JMAP journal is older than what clients may hold, so its
	/// header must not come back: neither the archived one nor the one a
	/// `--force` restore would leave in place. Without it the journal starts
	/// a new epoch and every client resyncs instead of trusting rewound
	/// positions.
	#[test]
	fn lay_files_drops_the_jmap_journal_header() {
		let data_dir = tempfile::tempdir().expect("tempdir");
		let account = data_dir.path().join("accounts/alice");
		std::fs::create_dir_all(&account).expect("account dir");
		std::fs::write(account.join(".jmap_state"), "777 0\n").expect("live header");
		let entries = vec![
			(
				"data/accounts/alice/.jmap_changes".to_string(),
				0o600_u32,
				b"1 e c 00000000-0000-0000-0000-000000000001\n".to_vec(),
			),
			(
				"data/accounts/alice/.jmap_state".to_string(),
				0o600_u32,
				b"777 0\n".to_vec(),
			),
		];
		lay_files(&entries, data_dir.path()).expect("lay_files");

		assert!(account.join(".jmap_changes").is_file(), "journal restored");
		assert!(
			!account.join(".jmap_state").exists(),
			"the journal header must not survive a restore"
		);
		let position = crate::imap::changelog::current(&account).expect("current");
		assert_ne!(
			position.epoch, 777,
			"the restored journal must start a new epoch"
		);
	}
}
