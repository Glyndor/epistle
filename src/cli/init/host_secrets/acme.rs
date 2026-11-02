//! Where the ACME account key lives, for each layout of the stack.
//!
//! Without the certificates container `mail` renews and reads the key at
//! `<data_dir>/acme/account.key`. With it, only `certs` mounts the key, at
//! `secrets/acme_account.key` beside data_dir, because `mail` mounts
//! data_dir. Switching copies the key to the place the new layout reads,
//! never moves it: the copy the old layout read is removed only once the
//! new one is verified ([`retire_data_dir_copy`]), so an account key is
//! never lost to a switch that fails halfway. Two copies that differ are
//! never reconciled here; the operator keeps the one the CA knows.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Read a key file, `None` when there is nothing at `path`. Anything there
/// that is not a regular file is refused rather than followed.
fn read_key(path: &Path) -> Result<Option<Vec<u8>>, String> {
	match fs::symlink_metadata(path) {
		Ok(metadata) if metadata.file_type().is_file() => fs::read(path)
			.map(Some)
			.map_err(|error| format!("cannot read {}: {error}", path.display())),
		Ok(_) => Err(format!(
			"{} is not a regular file; put the ACME account key there by hand",
			path.display()
		)),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(format!("cannot read {}: {error}", path.display())),
	}
}

/// Owner-only directory, created when missing.
fn private_dir(path: &Path) -> Result<(), String> {
	fs::create_dir_all(path)
		.and_then(|()| super::restrict(path, 0o700))
		.map_err(|error| format!("cannot prepare {}: {error}", path.display()))
}

/// Copy the key from `from` to `to` unless `to` already holds it. Two
/// different keys are refused by name.
fn copy_key(from: &Path, to: &Path) -> Result<Option<String>, String> {
	let source = read_key(from)?;
	match (read_key(to)?, source) {
		(Some(existing), Some(source)) if existing != source => Err(format!(
			"{} and {} hold different ACME account keys; keep the one the authority knows, \
			 delete the other and run this again",
			from.display(),
			to.display()
		)),
		(Some(_), _) | (None, None) => Ok(None),
		(None, Some(bytes)) => {
			if let Some(parent) = to.parent() {
				private_dir(parent)?;
			}
			crate::storage::write_secret(to, &bytes)
				.map_err(|error| format!("cannot write {}: {error}", to.display()))?;
			Ok(Some(format!(
				"copied the ACME account key from {} to {}",
				from.display(),
				to.display()
			)))
		}
	}
}

/// The directories `certs` mounts from data_dir, which a bind mount needs to
/// exist before the container starts.
pub(crate) fn split_dirs(data_dir: &Path) -> [PathBuf; 2] {
	let tlsa = crate::dns::tlsa::state_path(data_dir);
	[
		crate::acme::renew::pair_dir(data_dir),
		tlsa.parent().map_or(tlsa.clone(), Path::to_path_buf),
	]
}

/// Put the account key where the layout reads it: with `certs`, in
/// `secrets/` (copied from data_dir, or created when there is none
/// anywhere, since the container mounts it read-only and cannot create it),
/// plus the directories `certs` mounts; without, back under data_dir when
/// only `secrets/` holds it. One line per thing done.
pub(crate) fn place(data_dir: &Path, certs: bool) -> Result<Vec<String>, String> {
	let in_data_dir = crate::acme::renew::account_key_path(data_dir);
	let in_secrets = super::acme_account_key(data_dir);
	let mut lines = Vec::new();
	if certs {
		for dir in split_dirs(data_dir) {
			private_dir(&dir)?;
		}
		lines.extend(copy_key(&in_data_dir, &in_secrets)?);
		if read_key(&in_secrets)?.is_none() {
			private_dir(&super::dir(data_dir))?;
			crate::acme::renew::load_or_create_account_key_at(&in_secrets)
				.map_err(|error| format!("cannot create {}: {error}", in_secrets.display()))?;
			lines.push(format!(
				"created the ACME account key {}",
				in_secrets.display()
			));
		}
	} else {
		lines.extend(copy_key(&in_secrets, &in_data_dir)?);
	}
	Ok(lines)
}

/// Remove the copy under data_dir once the certificates container runs:
/// `mail` mounts data_dir, so a key left there is a key `mail` can read.
/// Only a copy identical to the one in `secrets/` is removed.
pub(crate) fn retire_data_dir_copy(data_dir: &Path) -> Result<Option<String>, String> {
	let in_data_dir = crate::acme::renew::account_key_path(data_dir);
	let in_secrets = super::acme_account_key(data_dir);
	match (read_key(&in_data_dir)?, read_key(&in_secrets)?) {
		(None, _) => Ok(None),
		(Some(_), None) => Err(format!(
			"{} is the only ACME account key; it stays until {} holds it",
			in_data_dir.display(),
			in_secrets.display()
		)),
		(Some(left), Some(kept)) if left != kept => Err(format!(
			"{} and {} hold different ACME account keys; keep the one the authority knows and \
			 delete the other",
			in_data_dir.display(),
			in_secrets.display()
		)),
		(Some(_), Some(_)) => {
			fs::remove_file(&in_data_dir)
				.map_err(|error| format!("cannot remove {}: {error}", in_data_dir.display()))?;
			Ok(Some(format!(
				"removed {}; the certificates container reads {}",
				in_data_dir.display(),
				in_secrets.display()
			)))
		}
	}
}
