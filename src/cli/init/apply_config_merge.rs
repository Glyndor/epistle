//! Merge the desired `Config` with whatever the operator already has
//! on disk, and stage the resulting bytes through a sibling file so a
//! half-written config never lands at its destination. Sister to
//! `apply_config.rs` because that file was at the per-file line limit
//! once the listener array grew to include imaps, submissions, and
//! the optional `acme` listener; the merge / staging block was the
//! largest self-contained section that could lift out without changing
//! any of the call sites.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::init::apply::ApplyError;
use crate::config::Config;

use super::apply_config::{ExistingConfig, INIT_MANAGED_KEYS, read_config};

/// Merge the desired TOML with whatever is already on disk at
/// `path`. Three outcomes: no file on disk (write the desired one);
/// same shape and content (skip and re-validate, in case the
/// on-disk file would not pass `Config::load`); same shape with
/// different values (rewrite through the staging path).
#[cfg(test)]
pub(crate) fn merge_with_existing(
	path: &Path,
	desired: &str,
	keep_existing_listeners: bool,
) -> Result<super::apply_config::ConfigWrite, ApplyError> {
	let existing = read_config(path)?;
	merge_with_read_config(path, desired, keep_existing_listeners, existing.as_ref())
}

/// Merge and validate the bytes captured from the verified descriptor.
pub(crate) fn merge_with_read_config(
	path: &Path,
	desired: &str,
	keep_existing_listeners: bool,
	existing: Option<&ExistingConfig>,
) -> Result<super::apply_config::ConfigWrite, ApplyError> {
	let desired_value: toml::Value =
		toml::from_str(desired).map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	match existing {
		Some(opened) => {
			let existing = &opened.text;
			let existing_value: toml::Value = parsed(existing).map_err(|e| {
				ApplyError::ConfigRead(path.to_path_buf(), std::io::Error::other(e.to_string()))
			})?;
			let merged = reconcile(existing_value, desired_value, keep_existing_listeners);
			if merged == parsed(existing)? {
				if let Err(error) = opened.validate(path) {
					return Err(ApplyError::ConfigInvalid(format!(
						"existing config at {} would be left untouched but is invalid: {}",
						path.display(),
						error
					)));
				}
				Ok(super::apply_config::ConfigWrite::Identical)
			} else {
				write_config_value(path, &merged)?;
				Ok(super::apply_config::ConfigWrite::Updated)
			}
		}
		None => {
			write_validated_config(path, desired)?;
			Ok(super::apply_config::ConfigWrite::Wrote)
		}
	}
}

/// Reconcile a desired TOML value with an existing one. Every key
/// listed in `INIT_MANAGED_KEYS` is removed from the root table of
/// the existing value (so the desired config can drop a previously
/// managed entry that the operator no longer wants) and replaced
/// from the desired value when present there. Keys not in that list
/// are preserved as the operator added them. The removal applies
/// at the root only: a nested operator table that happens to carry
/// a key whose name matches a managed key is preserved verbatim,
/// because `init` does not own the contents of nested tables.
///
/// When `keep_existing_listeners` is `true`, the `listeners` key is
/// skipped on both sides: the existing array survives untouched and
/// the desired one is dropped. The flag is set only when the
/// existing config already carries a non-empty `listeners` array on
/// disk.
///
/// Tables are reconciled recursively for keys the operator and
/// `init` both write; arrays are replaced wholesale because listeners
/// and the dns section are managed as a whole by `init`.
pub(crate) fn reconcile(
	existing: toml::Value,
	desired: toml::Value,
	keep_existing_listeners: bool,
) -> toml::Value {
	use toml::Value;
	match (existing, desired) {
		(Value::Table(mut existing_table), Value::Table(desired_table)) => {
			for key in INIT_MANAGED_KEYS {
				if *key == "listeners" && keep_existing_listeners {
					continue;
				}
				existing_table.remove(*key);
			}
			if !desired_table.contains_key("database")
				&& existing_table
					.get("database")
					.and_then(|db| db.get("url"))
					.and_then(Value::as_str)
					== Some(super::apply_config::STACK_DATABASE_URL)
			{
				existing_table.remove("database");
			}
			for (key, value) in desired_table {
				if key == "listeners" && keep_existing_listeners {
					continue;
				}
				let new = match existing_table.remove(&key) {
					Some(existing_inner) => reconcile_inner(existing_inner, value),
					None => value,
				};
				existing_table.insert(key, new);
			}
			Value::Table(existing_table)
		}
		(_, desired) => desired,
	}
}

/// Recurse into a nested table without applying the managed-key
/// removal. The root table is the only place `init` owns keys by
/// name, so a nested operator table keeps every key it had.
fn reconcile_inner(existing: toml::Value, desired: toml::Value) -> toml::Value {
	use toml::Value;
	match (existing, desired) {
		(Value::Table(mut existing_table), Value::Table(desired_table)) => {
			for (key, value) in desired_table {
				let new = match existing_table.remove(&key) {
					Some(existing_inner) => reconcile_inner(existing_inner, value),
					None => value,
				};
				existing_table.insert(key, new);
			}
			Value::Table(existing_table)
		}
		(_, desired) => desired,
	}
}

fn parsed(text: &str) -> Result<toml::Value, ApplyError> {
	toml::from_str(text).map_err(|error| ApplyError::ConfigEncode(error.to_string()))
}

/// Discover listeners without validating unrelated settings that the merge
/// may replace, such as an obsolete database password path.
pub(crate) fn existing_operators_listeners(
	path: &Path,
) -> Result<Option<Vec<crate::config::Listener>>, ApplyError> {
	let existing = read_config(path)?;
	listeners_from_existing(path, existing.as_ref())
}

pub(crate) fn listeners_from_existing(
	path: &Path,
	existing: Option<&ExistingConfig>,
) -> Result<Option<Vec<crate::config::Listener>>, ApplyError> {
	let Some(existing) = existing else {
		return Ok(None);
	};
	let text = &existing.text;
	let value: toml::Value = match toml::from_str(text) {
		Ok(value) => value,
		Err(_) => return Ok(None),
	};
	let Some(arr) = value.get("listeners").and_then(|v| v.as_array()) else {
		return Ok(None);
	};
	if arr.is_empty() {
		return Ok(None);
	}
	let mut out = Vec::with_capacity(arr.len());
	for entry in arr {
		let listener: crate::config::Listener = entry.clone().try_into().map_err(|error| {
			ApplyError::ConfigInvalid(format!(
				"existing listener in {} does not parse: {error}",
				path.display()
			))
		})?;
		out.push(listener);
	}
	Ok(Some(out))
}

/// Write `bytes` to `path` after staging them on a sibling file with
/// a random suffix, validating the candidate through `Config::load`,
/// and atomically renaming onto `path`. The staging filename cannot
/// collide with `config_path` (it always carries a random hex suffix)
/// and the staging file is created with `O_EXCL` at mode `0600` from
/// the very first byte, so it never has a wider-mode lifetime. The
/// destination is never touched when the candidate does not validate.
/// A `config_path` that resolves through a symlink is refused with an
/// actionable message; symlinks can be silently replaced in ways the
/// operator does not see, so the run stops before any effect rather
/// than guessing what the operator wanted.
pub(super) fn write_validated_config(path: &Path, bytes: &str) -> Result<(), ApplyError> {
	#[cfg(unix)]
	{
		match fs::symlink_metadata(path) {
			Ok(meta) if meta.file_type().is_symlink() => {
				return Err(ApplyError::ConfigSymlink(path.to_path_buf()));
			}
			Ok(_) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(ApplyError::ConfigRead(path.to_path_buf(), error)),
		}
	}
	let parent = path.parent().ok_or_else(|| {
		ApplyError::ConfigInvalid(format!(
			"config_path {} has no parent directory",
			path.display()
		))
	})?;
	let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
		ApplyError::ConfigInvalid(format!(
			"config_path {} has no usable file name",
			path.display()
		))
	})?;
	let (created, staging) = create_unique_staging(parent, file_name, bytes)?;
	match Config::load(&staging) {
		Ok(_) => {}
		Err(error) => {
			if created {
				let _ = fs::remove_file(&staging);
			}
			return Err(ApplyError::ConfigInvalid(error.to_string()));
		}
	}
	if let Err(error) = fs::rename(&staging, path) {
		if created {
			let _ = fs::remove_file(&staging);
		}
		return Err(ApplyError::ConfigWrite(path.to_path_buf(), error));
	}
	Ok(())
}

/// Create a unique staging file under `parent` derived from
/// `file_name` plus a random hex suffix. The file is opened with
/// `O_EXCL` at mode `0600` from the start: a pre-existing file at
/// the chosen name fails creation, so the operator can never lose a
/// sibling at a deterministic staging basename. Returns whether
/// this call created the file (so the caller knows it is safe to
/// clean up on a later error).
fn create_unique_staging(
	parent: &Path,
	file_name: &str,
	bytes: &str,
) -> Result<(bool, PathBuf), ApplyError> {
	create_unique_staging_with(
		parent,
		file_name,
		bytes,
		&mut random_hex_suffix,
		write_and_sync,
	)
}

/// Same as `create_unique_staging` but the suffix source and the
/// byte-write step are injected so the test can drive a controlled
/// collision sequence and a forced write failure. Production code
/// uses `create_unique_staging` and gets the real CSPRNG and the
/// `write_all` + `sync_all` step.
pub(super) fn create_unique_staging_with(
	parent: &Path,
	file_name: &str,
	bytes: &str,
	next_suffix: &mut dyn FnMut() -> String,
	write: fn(&mut fs::File, &[u8]) -> std::io::Result<()>,
) -> Result<(bool, PathBuf), ApplyError> {
	let mut opts = fs::OpenOptions::new();
	opts.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		opts.mode(0o600);
	}
	// The random suffix must be drawn inside the loop: the previous
	// shape held the suffix constant across all sixteen attempts and
	// the `AlreadyExists` arm could never fire on a different
	// candidate, so the retry loop was inert and a pre-existing
	// sibling at the first candidate name stopped the call.
	for _attempt in 0..16u32 {
		let suffix = next_suffix();
		let staging = parent.join(format!("{file_name}.config.tmp.{suffix}"));
		match opts.open(&staging) {
			Ok(mut file) => {
				// A guard that unlinks the staging file on every
				// error path: a write_all or sync_all failure must
				// not leave the partial file behind, because the
				// file can hold an inline DNS token and the next
				// run would block on its `O_EXCL` blocker. The
				// guard is disarmed just before the success return
				// so the caller's rename can move the staging
				// file onto the destination.
				let guard = StagingGuard {
					path: staging.clone(),
					armed: true,
				};
				if let Err(error) = write(&mut file, bytes.as_bytes()) {
					return Err(ApplyError::ConfigWrite(staging, error));
				}
				guard.disarm();
				return Ok((true, staging));
			}
			Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
			Err(error) => return Err(ApplyError::ConfigWrite(staging, error)),
		}
	}
	Err(ApplyError::ConfigWrite(
		parent.join(format!("{file_name}.config.tmp")),
		std::io::Error::other("could not allocate a unique staging filename after 16 attempts"),
	))
}

fn write_and_sync(file: &mut fs::File, bytes: &[u8]) -> std::io::Result<()> {
	file.write_all(bytes)?;
	file.sync_all()
}

/// RAII handle that removes the staging file on drop unless
/// `disarm` is called. The `O_EXCL` create and the early write_all
/// errors return paths the caller wants surfaced; if any of those
/// arms fires before the rename, the partial file is unlinked
/// instead of left behind as a `0600` token in the operator's
/// directory.
struct StagingGuard {
	path: PathBuf,
	armed: bool,
}

impl StagingGuard {
	fn disarm(mut self) {
		self.armed = false;
	}
}

impl Drop for StagingGuard {
	fn drop(&mut self) {
		if self.armed {
			let _ = fs::remove_file(&self.path);
		}
	}
}

/// Twelve hex digits drawn from the system CSPRNG. The CSPRNG cannot
/// fail on a well-formed host, but `init` only ever needs a unique
/// suffix; if it ever did, the fallback returns the constant
/// `424242424242` on every call, so the retry loop never finds a
/// free candidate and surfaces an `ApplyError::ConfigWrite` after
/// sixteen attempts.
fn random_hex_suffix() -> String {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 6];
	if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
		bytes = [0x42; 6];
	}
	let mut out = String::with_capacity(12);
	for byte in bytes {
		out.push_str(&format!("{byte:02x}"));
	}
	out
}

/// Change one listener without replacing unrelated configuration.
pub(crate) fn set_listener_enabled(
	path: &Path,
	kind: crate::config::ListenerKind,
	enabled: bool,
) -> Result<bool, ApplyError> {
	use crate::config::ListenerKind;
	if kind == ListenerKind::Smtp && !enabled {
		return Err(ApplyError::ConfigInvalid(
			"smtp cannot be disabled: inbound mail needs it".into(),
		));
	}
	let opened = read_config(path)?.ok_or_else(|| {
		ApplyError::ConfigRead(
			path.to_path_buf(),
			std::io::Error::from(std::io::ErrorKind::NotFound),
		)
	})?;
	let current = opened
		.validate(path)
		.map_err(|e| ApplyError::ConfigInvalid(e.to_string()))?;
	if current
		.listeners
		.iter()
		.any(|listener| listener.kind == kind)
		== enabled
	{
		return Ok(false);
	}
	let mut value = parsed(&opened.text)?;
	let listeners = value
		.as_table_mut()
		.ok_or_else(|| ApplyError::ConfigInvalid("config must be a table".into()))?
		.entry("listeners")
		.or_insert_with(|| toml::Value::Array(Vec::new()))
		.as_array_mut()
		.ok_or_else(|| ApplyError::ConfigInvalid("listeners must be an array".into()))?;
	if enabled {
		let addr = if kind == ListenerKind::Api {
			std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
		} else {
			current
				.listeners
				.iter()
				.find(|listener| listener.kind == ListenerKind::Smtp)
				.map(|listener| listener.addr)
				.unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
		};
		let mut listener = toml::Table::new();
		listener.insert("kind".into(), toml::Value::String(kind.as_str().into()));
		listener.insert("addr".into(), toml::Value::String(addr.to_string()));
		listeners.push(toml::Value::Table(listener));
	} else {
		listeners.retain(|listener| {
			listener.get("kind").and_then(toml::Value::as_str) != Some(kind.as_str())
		});
	}
	write_config_value(path, &value)?;
	Ok(true)
}

fn write_config_value(path: &Path, value: &toml::Value) -> Result<(), ApplyError> {
	let serialized =
		toml::to_string(value).map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	write_validated_config(path, &serialized)
}

#[cfg(test)]
#[path = "apply_config_tests_service.rs"]
mod tests_service;
