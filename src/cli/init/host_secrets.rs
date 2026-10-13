//! Keys that stay out of data_dir.
//!
//! `mail` mounts data_dir read-write and `epistle backup` archives it, so a
//! key kept there is writable by the server and travels in every backup. The
//! at-rest storage key and the OAuth signing key live instead in `secrets`,
//! next to data_dir (`/var/lib/glyndor/epistle/secrets` for the packaged
//! layout), and reach `mail` as read-only compose secrets mounted at the same
//! path. The host commands (`export`, `import`, `verify`, `archive`) read the
//! same config on the host, so the path has to be the same on both sides.
//!
//! Installs from before this layout have both keys under `data_dir/keys`;
//! [`move_legacy_keys`] moves them and [`repoint_config`] rewrites a config
//! that named the old place.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The file name of the at-rest storage key.
pub(crate) const STORAGE_KEY: &str = "storage.key";
/// The file name of the OAuth ES256 signing key.
pub(crate) const OAUTH_SIGNING_KEY: &str = "oauth_signing.key";

/// The directory: `secrets` beside data_dir.
pub(crate) fn dir(data_dir: &Path) -> PathBuf {
	data_dir.parent().unwrap_or(Path::new("/")).join("secrets")
}

/// Where the at-rest storage key lives.
pub(crate) fn storage_key(data_dir: &Path) -> PathBuf {
	dir(data_dir).join(STORAGE_KEY)
}

/// Where the OAuth signing key lives.
pub(crate) fn oauth_signing_key(data_dir: &Path) -> PathBuf {
	dir(data_dir).join(OAUTH_SIGNING_KEY)
}

/// Where an install from before this layout kept `name`.
pub(crate) fn legacy(data_dir: &Path, name: &str) -> PathBuf {
	data_dir.join("keys").join(name)
}

/// The path `name` is read from right now: the new place when anything is
/// there, else the old one when anything is there, else the new place.
pub(crate) fn effective(data_dir: &Path, name: &str) -> PathBuf {
	let new = dir(data_dir).join(name);
	let old = legacy(data_dir, name);
	if fs::symlink_metadata(&new).is_err() && fs::symlink_metadata(&old).is_ok() {
		old
	} else {
		new
	}
}

/// Create the directory owner-only and move both keys out of
/// `data_dir/keys`. Returns each `(from, to)` moved. A key already in the
/// new place with the same bytes only has its old copy removed; a different
/// one is left for the operator to decide, and so is anything at the old
/// path that is not a regular file. Running it again moves nothing.
pub(crate) fn move_legacy_keys(data_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>, String> {
	let target = dir(data_dir);
	fs::create_dir_all(&target)
		.and_then(|()| restrict(&target, 0o700))
		.map_err(|error| format!("cannot prepare {}: {error}", target.display()))?;
	let mut moved = Vec::new();
	for name in [STORAGE_KEY, OAUTH_SIGNING_KEY] {
		let (old, new) = (legacy(data_dir, name), target.join(name));
		let metadata = match fs::symlink_metadata(&old) {
			Ok(metadata) => metadata,
			Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
			Err(error) => return Err(format!("cannot read {}: {error}", old.display())),
		};
		if !metadata.file_type().is_file() {
			return Err(format!(
				"{} is not a regular file; move the key to {} by hand",
				old.display(),
				new.display()
			));
		}
		let bytes =
			fs::read(&old).map_err(|error| format!("cannot read {}: {error}", old.display()))?;
		match fs::read(&new) {
			Ok(existing) if existing == bytes => {}
			Ok(_) => {
				return Err(format!(
					"{} and {} differ; keep the one the server uses, delete the other and run this again",
					old.display(),
					new.display()
				));
			}
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				crate::storage::write_secret(&new, &bytes)
					.map_err(|error| format!("cannot write {}: {error}", new.display()))?;
				moved.push((old.clone(), new.clone()));
			}
			Err(error) => return Err(format!("cannot read {}: {error}", new.display())),
		}
		fs::remove_file(&old)
			.map_err(|error| format!("cannot remove {}: {error}", old.display()))?;
	}
	Ok(moved)
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> io::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> io::Result<()> {
	Ok(())
}

/// Add `[storage] encryption_key_file` to the config `init` is about to
/// merge, unless the existing config already sources the key elsewhere: a
/// file of the operator's own is never replaced, and a file would take
/// precedence over an `encryption_key_env` the operator chose. A config that
/// names the old place under data_dir gets the new one. `encrypt_at_rest` is
/// left as it is: turning encryption on stays the operator's choice.
pub(crate) fn with_storage_key(desired: String, existing: Option<&str>, data_dir: &Path) -> String {
	let current = existing
		.and_then(|text| toml::from_str::<toml::Value>(text).ok())
		.and_then(|value| value.get("storage").cloned());
	let file = current
		.as_ref()
		.and_then(|storage| storage.get("encryption_key_file"))
		.and_then(toml::Value::as_str);
	let env = current
		.as_ref()
		.is_some_and(|storage| storage.get("encryption_key_env").is_some());
	let ours = [legacy(data_dir, STORAGE_KEY), storage_key(data_dir)];
	let keep_operator_source = match file {
		Some(path) => !ours.iter().any(|candidate| candidate == Path::new(path)),
		None => env,
	};
	if keep_operator_source {
		return desired;
	}
	let mut desired = desired;
	if !desired.is_empty() && !desired.ends_with('\n') {
		desired.push('\n');
	}
	desired.push_str(&format!(
		"\n[storage]\nencryption_key_file = {}\n",
		toml::Value::String(storage_key(data_dir).display().to_string())
	));
	desired
}

/// Rewrite `[storage] encryption_key_file` and `[oauth] signing_key_file`
/// when they name the old place under data_dir, keeping every other byte of
/// the file. `Ok(None)` when nothing names the old place.
pub(crate) fn repoint_config(text: &str, data_dir: &Path) -> Result<Option<String>, String> {
	let mut document: toml_edit::DocumentMut = text
		.parse()
		.map_err(|error| format!("cannot parse the config: {error}"))?;
	let mut changed = false;
	for (table, key, name) in [
		("storage", "encryption_key_file", STORAGE_KEY),
		("oauth", "signing_key_file", OAUTH_SIGNING_KEY),
	] {
		let old = legacy(data_dir, name);
		let Some(item) = document.get_mut(table).and_then(|table| table.get_mut(key)) else {
			continue;
		};
		if item.as_str().map(Path::new) == Some(old.as_path()) {
			let decor = item.as_value().map(|value| value.decor().clone());
			let mut value = toml_edit::Value::from(dir(data_dir).join(name).display().to_string());
			if let Some(decor) = decor {
				*value.decor_mut() = decor;
			}
			*item = toml_edit::Item::Value(value);
			changed = true;
		}
	}
	Ok(changed.then(|| document.to_string()))
}

#[cfg(test)]
#[path = "host_secrets_tests.rs"]
mod tests;
