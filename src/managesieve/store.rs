//! Per-account Sieve script storage for ManageSieve (RFC 5804).
//!
//! Scripts live at `<data_dir>/accounts/<account>/sieve/<name>.sieve`. The
//! active script's name is recorded in `sieve/.active`, and its content is
//! mirrored to `<account>/filter.sieve` — the path the delivery pipeline reads
//! — so activating a script through ManageSieve takes effect immediately.

use std::fs;
use std::path::{Path, PathBuf};

/// A ManageSieve operation that failed in a way the protocol must report.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
	/// The script name is empty, too long, or contains a forbidden character.
	InvalidName,
	/// The named script does not exist.
	NoSuchScript,
	/// A script with the target name already exists.
	AlreadyExists,
	/// The script is active and so cannot be deleted.
	ActiveScript,
	/// The script text does not parse as Sieve. Carries a human reason.
	InvalidScript(String),
	/// An underlying filesystem error.
	Io,
}

/// Metadata for one stored script.
pub struct ScriptInfo {
	/// The script name (without the `.sieve` suffix).
	pub name: String,
	/// Whether this is the active script.
	pub active: bool,
}

/// Storage for one account's named Sieve scripts.
pub struct ScriptStore {
	account_dir: PathBuf,
	sieve_dir: PathBuf,
}

impl ScriptStore {
	/// Open the store for `account` under `accounts_root` (`data_dir/accounts`).
	pub fn new(accounts_root: &Path, account: &str) -> Self {
		let account_dir = accounts_root.join(account);
		let sieve_dir = account_dir.join("sieve");
		Self {
			account_dir,
			sieve_dir,
		}
	}

	/// Validate a script name and map it to its on-disk path. Rejects empty,
	/// over-long, control-character and path-separator names so a name can
	/// never escape the script directory (RFC 5804 §1.6, plus path safety).
	fn script_path(&self, name: &str) -> Result<PathBuf, StoreError> {
		if name.is_empty()
			|| name.len() > 128
			|| name == "."
			|| name == ".."
			|| name
				.chars()
				.any(|c| c.is_control() || c == '/' || c == '\\')
		{
			return Err(StoreError::InvalidName);
		}
		Ok(self.sieve_dir.join(format!("{name}.sieve")))
	}

	/// Parse `script` as Sieve, returning a human-readable reason on failure.
	pub fn validate(script: &str) -> Result<(), StoreError> {
		let tokens = crate::sieve::lexer::tokenize(script)
			.map_err(|error| StoreError::InvalidScript(format!("{error:?}")))?;
		crate::sieve::parser::parse(&tokens)
			.map_err(|error| StoreError::InvalidScript(format!("{error:?}")))?;
		Ok(())
	}

	/// The active script's name, if any.
	pub fn active_name(&self) -> Option<String> {
		fs::read_to_string(self.sieve_dir.join(".active"))
			.ok()
			.map(|name| name.trim().to_string())
			.filter(|name| !name.is_empty())
	}

	/// List every stored script with its active flag.
	pub fn list(&self) -> Result<Vec<ScriptInfo>, StoreError> {
		let active = self.active_name();
		let mut scripts = Vec::new();
		let entries = match fs::read_dir(&self.sieve_dir) {
			Ok(entries) => entries,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(scripts),
			Err(_) => return Err(StoreError::Io),
		};
		for entry in entries.flatten() {
			let file_name = entry.file_name();
			let name = file_name.to_string_lossy();
			if let Some(stripped) = name.strip_suffix(".sieve") {
				scripts.push(ScriptInfo {
					name: stripped.to_string(),
					active: active.as_deref() == Some(stripped),
				});
			}
		}
		scripts.sort_by(|a, b| a.name.cmp(&b.name));
		Ok(scripts)
	}

	/// Read a script's contents.
	pub fn get(&self, name: &str) -> Result<String, StoreError> {
		let path = self.script_path(name)?;
		match fs::read_to_string(&path) {
			Ok(content) => Ok(content),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				Err(StoreError::NoSuchScript)
			}
			Err(_) => Err(StoreError::Io),
		}
	}

	/// Store `content` under `name`, replacing any existing script of that name.
	/// The script must parse. If it is the active script, the live copy is
	/// refreshed too.
	pub fn put(&self, name: &str, content: &str) -> Result<(), StoreError> {
		let path = self.script_path(name)?;
		Self::validate(content)?;
		fs::create_dir_all(&self.sieve_dir).map_err(|_| StoreError::Io)?;
		fs::write(&path, content).map_err(|_| StoreError::Io)?;
		if self.active_name().as_deref() == Some(name) {
			self.write_live(content)?;
		}
		Ok(())
	}

	/// Delete a script. Refuses to delete the active script (RFC 5804 §2.10).
	pub fn delete(&self, name: &str) -> Result<(), StoreError> {
		let path = self.script_path(name)?;
		if self.active_name().as_deref() == Some(name) {
			return Err(StoreError::ActiveScript);
		}
		match fs::remove_file(&path) {
			Ok(()) => Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				Err(StoreError::NoSuchScript)
			}
			Err(_) => Err(StoreError::Io),
		}
	}

	/// Rename `old` to `new`. `new` must not already exist; if `old` was
	/// active, the active marker follows the rename.
	pub fn rename(&self, old: &str, new: &str) -> Result<(), StoreError> {
		let old_path = self.script_path(old)?;
		let new_path = self.script_path(new)?;
		if !old_path.exists() {
			return Err(StoreError::NoSuchScript);
		}
		if new_path.exists() {
			return Err(StoreError::AlreadyExists);
		}
		fs::rename(&old_path, &new_path).map_err(|_| StoreError::Io)?;
		if self.active_name().as_deref() == Some(old) {
			self.set_active_marker(Some(new))?;
		}
		Ok(())
	}

	/// Make `name` the active script, or deactivate all when `None`
	/// (RFC 5804 §2.8: SETACTIVE with the empty string).
	pub fn set_active(&self, name: Option<&str>) -> Result<(), StoreError> {
		match name {
			Some(name) => {
				let content = self.get(name)?;
				self.write_live(&content)?;
				self.set_active_marker(Some(name))
			}
			None => {
				let _ = fs::remove_file(self.account_dir.join("filter.sieve"));
				self.set_active_marker(None)
			}
		}
	}

	/// Write the active script's content to the live `filter.sieve` path.
	fn write_live(&self, content: &str) -> Result<(), StoreError> {
		fs::create_dir_all(&self.account_dir).map_err(|_| StoreError::Io)?;
		fs::write(self.account_dir.join("filter.sieve"), content).map_err(|_| StoreError::Io)
	}

	/// Record (or clear) the active script name.
	fn set_active_marker(&self, name: Option<&str>) -> Result<(), StoreError> {
		let marker = self.sieve_dir.join(".active");
		match name {
			Some(name) => {
				fs::create_dir_all(&self.sieve_dir).map_err(|_| StoreError::Io)?;
				fs::write(&marker, name).map_err(|_| StoreError::Io)
			}
			None => {
				let _ = fs::remove_file(&marker);
				Ok(())
			}
		}
	}
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
