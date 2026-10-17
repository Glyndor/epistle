//! Per-account Sieve script storage, shared by ManageSieve (RFC 5804) and JMAP
//! (RFC 9661).
//!
//! Scripts live at `<data_dir>/accounts/<account>/sieve/<name>.sieve`. The
//! active script's name is recorded in `sieve/.active`, and its content is
//! mirrored to `<account>/filter.sieve` — the path the delivery pipeline reads
//! — so activating a script through ManageSieve takes effect immediately.

use std::fs;
use std::path::{Path, PathBuf};

use crate::util::path_component::AccountName;
use crate::util::path_containment::{contained, contained_child, contained_subdir};

/// The most octets one script may hold. It is the same number the ManageSieve
/// listener allows for a literal, and the one JMAP advertises as
/// `maxSizeScript`, so a script one protocol accepts the other accepts too.
pub const MAX_SCRIPT_BYTES: usize = 1 << 20;

/// The most scripts one account may store (`maxNumberScripts`). Every script
/// is a file, and `list` reads them all, so the count is bounded.
pub const MAX_SCRIPTS: usize = 50;

/// The longest script name, in Unicode scalar values (RFC 5804 section 1.6).
pub const MAX_NAME_CHARS: usize = 128;

/// The longest script name, in octets. The name is the file name, and the
/// atomic write stages a `.<name>.sieve.<uuid>.tmp` file next to it, which
/// must stay under the 255 octets a file name may have on common
/// filesystems. 200 leaves room for that staging name.
pub const MAX_NAME_BYTES: usize = 200;

/// Whether `name` is an acceptable script name: 1 to [`MAX_NAME_CHARS`]
/// characters and [`MAX_NAME_BYTES`] octets, none of them a control
/// character, a path separator, or U+2028 / U+2029 (RFC 9661 section 2.1
/// lists the controls U+0000-U+001F, U+007F-U+009F, U+2028 and U+2029), and
/// not `.` or `..`.
pub fn is_valid_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= MAX_NAME_BYTES
		&& name.chars().count() <= MAX_NAME_CHARS
		&& name != "."
		&& name != ".."
		&& !name
			.chars()
			.any(|c| c.is_control() || matches!(c, '/' | '\\' | '\u{2028}' | '\u{2029}'))
}

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
	/// The script is over [`MAX_SCRIPT_BYTES`].
	TooLarge,
	/// The account already holds [`MAX_SCRIPTS`] scripts.
	TooManyScripts,
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
	dirs: Option<Dirs>,
}

/// The two directories of one account's scripts, both vetted by the
/// containment check.
struct Dirs {
	account_dir: PathBuf,
	sieve_dir: PathBuf,
}

impl Dirs {
	fn open(accounts_root: &Path, account: &str) -> std::io::Result<Self> {
		let root = contained(accounts_root, accounts_root)?;
		let account_dir = contained_subdir(&root, AccountName::new(account)?.as_str())?;
		let sieve_dir = contained_child(&account_dir, "sieve")?;
		Ok(Self {
			account_dir,
			sieve_dir,
		})
	}
}

impl ScriptStore {
	/// Open the store for `account` under `accounts_root` (`data_dir/accounts`).
	///
	/// An account name that is not one plain directory name, or a path that
	/// leaves `accounts_root`, gives a store whose every operation reports
	/// [`StoreError::Io`].
	pub fn new(accounts_root: &Path, account: &str) -> Self {
		Self {
			dirs: Dirs::open(accounts_root, account).ok(),
		}
	}

	fn dirs(&self) -> Result<&Dirs, StoreError> {
		self.dirs.as_ref().ok_or(StoreError::Io)
	}

	/// Validate a script name and map it to its on-disk path. Rejects empty,
	/// over-long, control-character and path-separator names so a name can
	/// never escape the script directory (RFC 5804 §1.6, plus path safety).
	fn script_path(&self, name: &str) -> Result<PathBuf, StoreError> {
		if !is_valid_name(name) {
			return Err(StoreError::InvalidName);
		}
		contained_child(&self.dirs()?.sieve_dir, &format!("{name}.sieve"))
			.map_err(|_| StoreError::InvalidName)
	}

	/// Check `script` as every protocol does before storing it or reporting
	/// it valid: within [`MAX_SCRIPT_BYTES`], valid Sieve, and only requiring
	/// extensions the interpreter runs. A failure carries a reason that names
	/// the line and never repeats the script's own text.
	pub fn validate(script: &str) -> Result<(), StoreError> {
		super::store_check::check(script)
	}

	/// Whether a script called `name` of `size` octets could be stored now
	/// (RFC 5804 section 2.5, HAVESPACE).
	pub fn have_space(&self, name: &str, size: u64) -> Result<(), StoreError> {
		let path = self.script_path(name)?;
		if size > MAX_SCRIPT_BYTES as u64 {
			return Err(StoreError::TooLarge);
		}
		self.room_for(&path)
	}

	/// A script that is not yet stored needs a free slot; rewriting one that
	/// is needs none.
	fn room_for(&self, path: &Path) -> Result<(), StoreError> {
		if path.exists() || self.list()?.len() < MAX_SCRIPTS {
			Ok(())
		} else {
			Err(StoreError::TooManyScripts)
		}
	}

	/// The active script's name, if any.
	pub fn active_name(&self) -> Option<String> {
		let marker = contained_child(&self.dirs.as_ref()?.sieve_dir, ".active").ok()?;
		fs::read_to_string(marker)
			.ok()
			.map(|name| name.trim().to_string())
			.filter(|name| !name.is_empty())
	}

	/// List every stored script with its active flag.
	pub fn list(&self) -> Result<Vec<ScriptInfo>, StoreError> {
		let active = self.active_name();
		let mut scripts = Vec::new();
		let entries = match crate::util::fs_walk::read_dir(&self.dirs()?.sieve_dir) {
			Ok(entries) => entries,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(scripts),
			Err(_) => return Err(StoreError::Io),
		};
		for entry in entries.flatten() {
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
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
		self.room_for(&path)?;
		fs::create_dir_all(&self.dirs()?.sieve_dir).map_err(|_| StoreError::Io)?;
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
				if let Ok(live) = self.live_path() {
					let _ = fs::remove_file(live);
				}
				self.set_active_marker(None)
			}
		}
	}

	/// Write the active script's content to the live `filter.sieve` path.
	fn write_live(&self, content: &str) -> Result<(), StoreError> {
		fs::create_dir_all(&self.dirs()?.account_dir).map_err(|_| StoreError::Io)?;
		fs::write(self.live_path()?, content).map_err(|_| StoreError::Io)
	}

	/// The live `filter.sieve` the delivery pipeline reads.
	fn live_path(&self) -> Result<PathBuf, StoreError> {
		contained_child(&self.dirs()?.account_dir, "filter.sieve").map_err(|_| StoreError::Io)
	}

	/// Record (or clear) the active script name.
	fn set_active_marker(&self, name: Option<&str>) -> Result<(), StoreError> {
		let sieve_dir = &self.dirs()?.sieve_dir;
		let marker = contained_child(sieve_dir, ".active").map_err(|_| StoreError::Io)?;
		match name {
			Some(name) => {
				fs::create_dir_all(sieve_dir).map_err(|_| StoreError::Io)?;
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

#[cfg(test)]
#[path = "store_tests_limits.rs"]
mod limits_tests;

#[cfg(test)]
#[path = "store_tests_check.rs"]
mod check_tests;
