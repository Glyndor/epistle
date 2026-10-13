//! The database password `init` mints for the stack: where it lives, how
//! it is generated, and when an existing one is reused or refused.

use std::fs;
use std::path::{Path, PathBuf};

use super::super::apply::{ApplyError, Report, ReportStep};
use super::{compose_secrets_dir, db_password_path};

/// Mint a fresh 32-character alphanumeric password from the system
/// CSPRNG. The alphabet excludes look-alikes (no `0`/`O`/`1`/`l`)
/// so a value copied off the operator's screen is read back
/// correctly. Returns `None` when the CSPRNG cannot produce bytes;
/// the apply phase surfaces that as `ApplyError::Rng` and the run
/// exits 1 with the report of what already landed.
pub(in crate::cli::init) fn generate_db_password() -> Option<String> {
	use ring::rand::SecureRandom;
	const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
	let mut bytes = [0u8; 32];
	ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
	let mut out = String::with_capacity(32);
	for byte in bytes {
		// The bias from a 256-byte modular reduction against a
		// 32-character alphabet is small enough to ignore: every
		// character has at least 6 candidates (256 / 32 = 8) and
		// the worst case is 8 vs 9, well within a CSPRNG's noise
		// floor.
		out.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
	}
	Some(out)
}

/// Lay down `<data_dir>/secrets/epistle_db_password` and the
/// `<data_dir>/secrets` directory. Called only when
/// `services.database` is `true`.
///
/// The file is reused byte-for-byte when it already exists and
/// is a regular file with non-empty content AND it can actually
/// be read. Rotating it would lock epistle out of the existing
/// database: PostgreSQL keeps the old credential in its volume
/// and a new password would never be honoured.
///
/// Only a path that does not exist at all (the result of
/// `symlink_metadata` is `NotFound`) is regenerated. Every
/// other entry at the path is a present-but-unusable shape the
/// operator put there on purpose (or by accident) and the apply
/// phase refuses rather than silently rewriting it:
/// - a regular file with empty content (a leftover zero-length
///   file from an earlier half-written run);
/// - a symlink (broken or not) at the path (a symlink target
///   could be a file the operator points at from a backup, and
///   replacing the symlink with a fresh file would lose the
///   link without warning);
/// - a directory, fifo, device, or socket in place of the file
///   (`fs::read` returns `Is a directory`, a fifo would block
///   on the read, a device node would expose the wrong API);
/// - a non-empty file that cannot be read (`mode 0o000`, an
///   unreadable mount, an EIO error, ...).
///
/// Each refusal surfaces as
/// [`ApplyError::ExistingSecretUnreadable`] and names the path
/// the operator must repair by hand. The Postgres entrypoint
/// still has the old credential in its volume; minting a fresh
/// password would lock the database out from under the operator.
///
/// Returns the password path; the bytes themselves are not
/// surfaced to the apply phase.
pub(in crate::cli::init) fn ensure_db_password(
	data_dir: &Path,
	report: &mut Report,
) -> Result<PathBuf, ApplyError> {
	ensure_db_password_with_probe(data_dir, report, podman_volume_exists)
}

fn podman_volume_exists(volume: &str) -> std::io::Result<bool> {
	let output = std::process::Command::new("podman")
		.args(["volume", "exists", volume])
		.output()?;
	match output.status.code() {
		Some(0) => Ok(true),
		Some(1) => Ok(false),
		_ => Err(std::io::Error::other(format!(
			"podman volume exists {volume} failed with status {}; verify Podman is available and rerun init",
			output.status
		))),
	}
}

pub(in crate::cli::init) fn ensure_db_password_with_probe(
	data_dir: &Path,
	report: &mut Report,
	probe: impl FnOnce(&str) -> std::io::Result<bool>,
) -> Result<PathBuf, ApplyError> {
	let dir = compose_secrets_dir(data_dir);
	fs::create_dir_all(&dir).map_err(|error| ApplyError::KeyWrite(dir.clone(), error))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
			.map_err(|error| ApplyError::KeyWrite(dir.clone(), error))?;
	}
	let path = db_password_path(data_dir);
	match fs::symlink_metadata(&path) {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			// The existing database retains its original password even if the host file is lost.
			let volume = "epistle_epistle-pgdata";
			if probe(volume).map_err(|error| {
				ApplyError::DatabaseVolume(format!(
					"cannot check database volume {volume}: {error}"
				))
			})? {
				return Err(ApplyError::DatabaseVolume(format!(
					"database volume {volume} already exists but password file {} is missing; restore the password file from backup or remove the volume with `podman volume rm {volume}` and rerun init",
					path.display()
				)));
			}
			write_fresh_password(&path, report)
		}
		Err(error) => {
			// A `symlink_metadata` failure other than
			// `NotFound` is a precondition the apply phase
			// surfaces with its own diagnostic: an
			// unreadable parent, a permissions refusal on
			// the secrets directory, ...
			Err(ApplyError::ExistingSecretUnreadable(path, error))
		}
		Ok(metadata) => {
			// The path resolves to something. Only a regular
			// file with non-empty content is reusable; every
			// other shape is refused so the operator sees the
			// refusal rather than a silent rewrite.
			let file_type = metadata.file_type();
			if file_type.is_symlink() {
				return Err(ApplyError::ExistingSecretUnreadable(
					path,
					std::io::Error::other(
						"path is a symlink; remove it (or replace it with the file it pointed at) and rerun init",
					),
				));
			}
			if !file_type.is_file() {
				return Err(ApplyError::ExistingSecretUnreadable(
					path,
					std::io::Error::other("path is not a regular file; remove it and rerun init"),
				));
			}
			match fs::read(&path) {
				Ok(existing) if !existing.is_empty() => {
					// The file is a regular file with
					// non-empty content: PostgreSQL has
					// the matching password in its volume
					// and rotating it would lock
					// epistle out.
					report.steps.push(ReportStep::Reused(path.clone()));
					Ok(path)
				}
				Ok(_) => Err(ApplyError::ExistingSecretUnreadable(
					path,
					std::io::Error::other(
						"file is empty; restore the password file from backup, or remove both the database volume and file before rerunning init",
					),
				)),
				Err(error) => Err(ApplyError::ExistingSecretUnreadable(path, error)),
			}
		}
	}
}

/// Mint a fresh database password and write it under
/// `write_secret` so a crash mid-write cannot leave a
/// half-written secret in place. Returns the password path on
/// success; the bytes themselves are not surfaced.
fn write_fresh_password(path: &Path, report: &mut Report) -> Result<PathBuf, ApplyError> {
	let password =
		generate_db_password().ok_or_else(|| ApplyError::Rng("database password".to_string()))?;
	crate::storage::write_secret(path, password.as_bytes())
		.map_err(|error| ApplyError::KeyWrite(path.to_path_buf(), error))?;
	report.steps.push(ReportStep::Wrote(path.to_path_buf()));
	Ok(path.to_path_buf())
}

/// Test whether the database-password file the apply phase
/// would reuse is a regular file with non-empty content. The
/// plan uses this to mark the `DbPassword` step `reused: true`
/// only when the apply phase will actually reuse. A symlink
/// at the path, a directory, an empty file, or any other
/// present-but-unusable shape returns `false` here so the plan
/// says `generate` and the apply phase then refuses the entry
/// with [`ApplyError::ExistingSecretUnreadable`] before any
/// effect.
pub(in crate::cli::init) fn db_password_reused(data_dir: &Path) -> bool {
	let path = db_password_path(data_dir);
	let Ok(metadata) = fs::symlink_metadata(&path) else {
		return false;
	};
	if !metadata.file_type().is_file() {
		return false;
	}
	matches!(fs::read(&path), Ok(bytes) if !bytes.is_empty())
}

/// Lay down the password of the PostgreSQL admin role beside data_dir,
/// where mail cannot read it, or reuse the one already there. A cluster
/// initialised before the admin role existed gets that password from
/// `stack update`, which creates the role with it; a regenerated one is
/// only ever set by that same step, so losing it locks out nothing mail
/// needs.
pub(in crate::cli::init) fn ensure_db_admin_password(
	data_dir: &Path,
	report: &mut Report,
) -> Result<PathBuf, ApplyError> {
	let path = super::super::host_secrets::db_admin_password(data_dir);
	if let Some(dir) = path.parent() {
		fs::create_dir_all(dir).map_err(|error| ApplyError::KeyWrite(dir.to_path_buf(), error))?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
				.map_err(|error| ApplyError::KeyWrite(dir.to_path_buf(), error))?;
		}
	}
	match fs::symlink_metadata(&path) {
		Ok(metadata) if metadata.file_type().is_file() && metadata.len() > 0 => {
			report.steps.push(ReportStep::Reused(path.clone()));
			Ok(path)
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			write_fresh_password(&path, report)
		}
		Ok(_) => Err(ApplyError::ExistingSecretUnreadable(
			path,
			std::io::Error::other("not a non-empty regular file; remove it and rerun"),
		)),
		Err(error) => Err(ApplyError::ExistingSecretUnreadable(path, error)),
	}
}
