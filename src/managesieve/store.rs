//! Per-account Sieve script storage, shared by ManageSieve (RFC 5804) and JMAP
//! (RFC 9661).
//!
//! Scripts live at `<data_dir>/accounts/<account>/sieve/<name>.sieve`. The
//! active script's name is recorded in `sieve/.active`, and its content is
//! mirrored to `<account>/filter.sieve` — the path the delivery pipeline reads
//! — so activating a script through ManageSieve takes effect immediately.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::store_index::Index;
use super::store_names;
use crate::storage::lock::FileLock;
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

/// The longest script name, in octets: 128 characters of up to four octets
/// each (RFC 5804 section 1.6). A name past 200 octets is not the file name
/// (see `store_names`).
pub const MAX_NAME_BYTES: usize = 512;

/// Whether `name` is an acceptable script name: 1 to [`MAX_NAME_CHARS`]
/// characters and [`MAX_NAME_BYTES`] octets, none of them a control
/// character, a path separator, or U+2028 / U+2029 (RFC 9661 section 2.1
/// lists the controls U+0000-U+001F, U+007F-U+009F, U+2028 and U+2029), and
/// not `.` or `..`. A name does not start or end with white space and has
/// no bidirectional formatting character, since either makes it look like
/// another name, and it is in Unicode normal form C, the form Net-Unicode
/// (RFC 5198) names a client sends are in, so two spellings of one name are
/// not two scripts.
pub fn is_valid_name(name: &str) -> bool {
	use unicode_normalization::UnicodeNormalization;
	!name.is_empty()
		&& name.len() <= MAX_NAME_BYTES
		&& name.chars().count() <= MAX_NAME_CHARS
		&& name != "."
		&& name != ".."
		&& !store_names::is_reserved(name)
		&& !name.starts_with(char::is_whitespace)
		&& !name.ends_with(char::is_whitespace)
		&& !name.chars().any(|c| {
			c.is_control()
				|| matches!(c, '/' | '\\' | '\u{2028}' | '\u{2029}')
				|| crate::util::validation::is_bidi_or_invisible(c)
		}) && (name.is_ascii() || name.nfc().eq(name.chars()))
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
	/// The store is not at the state the caller expected: it changed since.
	StateMismatch,
	/// An underlying filesystem error.
	Io,
}

/// Metadata for one stored script.
pub struct ScriptInfo {
	/// The script name (without the `.sieve` suffix).
	pub name: String,
	/// Whether this is the active script.
	pub active: bool,
	/// The script's id: opaque, 32 hex digits, minted once and kept through
	/// rewrites and renames, so a client can follow a script across them.
	pub id: String,
	/// How many times the content has been written, from 1. Together with
	/// the id it names one version of the content (JMAP blob ids).
	pub rev: u64,
}

/// Storage for one account's named Sieve scripts.
pub struct ScriptStore {
	account: String,
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
			account: account.to_string(),
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
		contained_child(
			&self.dirs()?.sieve_dir,
			&format!("{}.sieve", store_names::stem(name)),
		)
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
		self.script_path(name)?;
		if size > MAX_SCRIPT_BYTES as u64 {
			return Err(StoreError::TooLarge);
		}
		let scripts = self.list()?;
		if scripts.len() < MAX_SCRIPTS || scripts.iter().any(|s| s.name == name) {
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
			.filter(|name| !name.is_empty())
	}

	/// List every stored script with its active flag, id and revision.
	pub fn list(&self) -> Result<Vec<ScriptInfo>, StoreError> {
		self.snapshot().map(|(_, scripts)| scripts)
	}

	/// The store's change counter: it moves whenever the set of scripts,
	/// their content, their names or the active one changes, by whichever
	/// protocol, and at no other time.
	pub fn state(&self) -> Result<u64, StoreError> {
		self.snapshot().map(|(state, _)| state)
	}

	/// The change counter and the scripts it counts, read together: the
	/// listing is exactly what the counter says it is.
	pub fn snapshot(&self) -> Result<(u64, Vec<ScriptInfo>), StoreError> {
		let Some(mut txn) = self.read_txn()? else {
			return Ok((0, Vec::new()));
		};
		let active = self.active_name();
		let scripts = txn
			.index
			.scripts
			.keys()
			.filter_map(|name| txn.info(name, active.as_deref()))
			.collect();
		// A reconcile that changed the index is a change, and is counted
		// before the listing is reported.
		txn.commit_in_place()?;
		Ok((txn.index.state, scripts))
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
		Self::validate(content)?;
		let mut txn = self.write_txn()?;
		let outcome = self.write_in(&mut txn, name, content, false);
		txn.finish(outcome)
	}

	/// Delete a script. Refuses to delete the active script (RFC 5804 §2.10).
	pub fn delete(&self, name: &str) -> Result<(), StoreError> {
		let mut txn = self.write_txn()?;
		let outcome = self.remove_in(&mut txn, name);
		txn.finish(outcome)
	}

	/// Rename `old` to `new`. `new` must not already exist; if `old` was
	/// active, the active marker follows the rename. The script keeps its id.
	pub fn rename(&self, old: &str, new: &str) -> Result<(), StoreError> {
		let mut txn = self.write_txn()?;
		let outcome = self.rename_in(&mut txn, old, new);
		txn.finish(outcome)
	}

	/// Write `content` as the script `name` inside `txn`. With `exclusive`, a
	/// script of that name already there is an error. A new name needs a free
	/// slot; a rewrite does not.
	fn write_in(
		&self,
		txn: &mut Txn,
		name: &str,
		content: &str,
		exclusive: bool,
	) -> Result<(), StoreError> {
		let path = self.script_path(name)?;
		let exists = txn.index.scripts.contains_key(name);
		if exists && exclusive {
			return Err(StoreError::AlreadyExists);
		}
		if !exists && txn.index.scripts.len() >= MAX_SCRIPTS {
			return Err(StoreError::TooManyScripts);
		}
		store_names::record(&self.dirs()?.sieve_dir, name).map_err(|_| StoreError::Io)?;
		crate::storage::write_secret(&path, content.as_bytes()).map_err(|_| StoreError::Io)?;
		txn.index.wrote(name);
		txn.changed = true;
		if self.active_name().as_deref() == Some(name) {
			self.write_live(content)?;
		}
		Ok(())
	}

	/// Remove the script `name` inside `txn`, unless it is the active one.
	fn remove_in(&self, txn: &mut Txn, name: &str) -> Result<(), StoreError> {
		let path = self.script_path(name)?;
		if self.active_name().as_deref() == Some(name) {
			return Err(StoreError::ActiveScript);
		}
		match fs::remove_file(&path) {
			Ok(()) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				return Err(StoreError::NoSuchScript);
			}
			Err(_) => return Err(StoreError::Io),
		}
		store_names::forget(&self.dirs()?.sieve_dir, name);
		txn.index.scripts.remove(name);
		txn.changed = true;
		Ok(())
	}

	/// Rename `old` to `new` inside `txn`, the active marker following.
	fn rename_in(&self, txn: &mut Txn, old: &str, new: &str) -> Result<(), StoreError> {
		let old_path = self.script_path(old)?;
		let new_path = self.script_path(new)?;
		if !old_path.exists() {
			return Err(StoreError::NoSuchScript);
		}
		if new_path.exists() {
			return Err(StoreError::AlreadyExists);
		}
		let dir = &self.dirs()?.sieve_dir;
		store_names::record(dir, new).map_err(|_| StoreError::Io)?;
		fs::rename(&old_path, &new_path).map_err(|_| StoreError::Io)?;
		store_names::forget(dir, old);
		txn.index.renamed(old, new);
		txn.changed = true;
		if self.active_name().as_deref() == Some(old) {
			self.set_active_marker(Some(new))?;
		}
		Ok(())
	}

	/// Make `name` the active script, or deactivate all when `None`
	/// (RFC 5804 §2.8: SETACTIVE with the empty string).
	pub fn set_active(&self, name: Option<&str>) -> Result<(), StoreError> {
		let mut txn = self.write_txn()?;
		let outcome = self.set_active_in(&mut txn, name);
		txn.finish(outcome)
	}

	/// Make `name` the active script inside `txn`, or deactivate all. Moving
	/// from one script to another writes the new live filter over the old one
	/// and then the marker: delivery finds a filter at every moment.
	fn set_active_in(&self, txn: &mut Txn, name: Option<&str>) -> Result<(), StoreError> {
		let was = self.active_name();
		let outcome = match name {
			Some(name) => self.get(name).and_then(|content| {
				self.write_live(&content)?;
				self.set_active_marker(Some(name))
			}),
			None => {
				if let Ok(live) = self.live_path() {
					let _ = fs::remove_file(live);
				}
				self.set_active_marker(None)
			}
		};
		txn.changed |= outcome.is_ok() && was.as_deref() != name;
		outcome
	}

	/// Write the active script's content to the live `filter.sieve` path.
	fn write_live(&self, content: &str) -> Result<(), StoreError> {
		fs::create_dir_all(&self.dirs()?.account_dir).map_err(|_| StoreError::Io)?;
		crate::storage::write_secret(&self.live_path()?, content.as_bytes())
			.map_err(|_| StoreError::Io)
	}

	/// The live `filter.sieve` the delivery pipeline reads.
	fn live_path(&self) -> Result<PathBuf, StoreError> {
		contained_child(&self.dirs()?.account_dir, "filter.sieve").map_err(|_| StoreError::Io)
	}

	/// Record (or clear) the active script name.
	fn set_active_marker(&self, name: Option<&str>) -> Result<(), StoreError> {
		let marker =
			contained_child(&self.dirs()?.sieve_dir, ".active").map_err(|_| StoreError::Io)?;
		match name {
			Some(name) => {
				crate::storage::write_secret(&marker, name.as_bytes()).map_err(|_| StoreError::Io)
			}
			None => {
				let _ = fs::remove_file(&marker);
				Ok(())
			}
		}
	}

	/// The scripts' directory, held under the account's lock with the index
	/// reconciled against it. `None` when the account has no scripts yet.
	fn read_txn(&self) -> Result<Option<Txn>, StoreError> {
		if !self.dirs()?.sieve_dir.is_dir() {
			return Ok(None);
		}
		self.write_txn().map(Some)
	}

	/// As [`Self::read_txn`], creating the directory when it is missing.
	fn write_txn(&self) -> Result<Txn, StoreError> {
		let dirs = self.dirs()?;
		fs::create_dir_all(&dirs.sieve_dir).map_err(|_| StoreError::Io)?;
		let lock = contained_child(&dirs.sieve_dir, ".lock").map_err(|_| StoreError::Io)?;
		crate::storage::lock::create_private(&lock).map_err(|_| StoreError::Io)?;
		let lock = crate::util::blocking::may_block(|| FileLock::acquire(&lock))
			.map_err(|_| StoreError::Io)?;
		let path = contained_child(&dirs.sieve_dir, ".index.json").map_err(|_| StoreError::Io)?;
		let mut index = Index::read(&path);
		let changed = index.reconcile(&self.names_on_disk()?);
		Ok(Txn {
			_lock: lock,
			path,
			index,
			changed,
		})
	}

	/// The names of the scripts present as files. A file whose name could
	/// not have been stored (it fails [`is_valid_name`]) is not a script.
	fn names_on_disk(&self) -> Result<BTreeSet<String>, StoreError> {
		let entries =
			crate::util::fs_walk::read_dir(&self.dirs()?.sieve_dir).map_err(|_| StoreError::Io)?;
		let mut names = BTreeSet::new();
		let active = self.active_name();
		let mut left_out = 0usize;
		let mut active_left_out = false;
		for entry in entries.flatten() {
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
			let Ok(file) = entry.file_name().into_string() else {
				continue;
			};
			let Some(name) = file.strip_suffix(".sieve") else {
				continue;
			};
			let hashed = store_names::original(&self.dirs()?.sieve_dir, name);
			// A file that is its own name holds a short name: a longer one
			// would be looked for under its hashed file name.
			let plain = hashed.is_none() && name.len() <= store_names::FILE_NAME_BYTES;
			let name = hashed.as_deref().unwrap_or(name);
			if (plain || hashed.is_some()) && is_valid_name(name) {
				names.insert(name.to_string());
			} else {
				left_out += 1;
				active_left_out |= active.as_deref() == Some(name);
			}
		}
		if left_out > 0 {
			self.warn_once("names", || {
				tracing::warn!(
					account = %self.account,
					left_out,
					active_left_out,
					"scripts whose names are not valid since a stricter name check are not listed; \
					 rename the files, or delete them. If the active script is one of them \
					 (active_left_out), it keeps running and can be switched off or replaced \
					 by activating another"
				);
			});
		}
		if names.len() > MAX_SCRIPTS {
			self.warn_once("count", || {
				tracing::warn!(
					account = %self.account,
					scripts = names.len(),
					limit = MAX_SCRIPTS,
					"the account holds more scripts than the limit; none can be added until some are deleted"
				);
			});
		}
		Ok(names)
	}

	/// Run `warn` the first time this process sees `kind` for this account's
	/// scripts: the store is read on every call, and a log line is for a
	/// change, not for each look.
	fn warn_once(&self, kind: &str, warn: impl FnOnce()) {
		static SEEN: std::sync::Mutex<BTreeSet<String>> = std::sync::Mutex::new(BTreeSet::new());
		let Ok(dirs) = self.dirs() else { return };
		let key = format!("{kind}:{}", dirs.sieve_dir.display());
		let first = SEEN
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.insert(key);
		if first {
			warn();
		}
	}
}

/// An operation in progress on an account's scripts: the account's lock,
/// held until [`Txn::commit`] or the drop, and the index as it will be
/// written.
struct Txn {
	_lock: FileLock,
	path: PathBuf,
	index: Index,
	/// Whether the operation changed anything the counter counts.
	changed: bool,
}

impl Txn {
	/// Write the index, then report `outcome`. The index is written even
	/// when a later step of the operation failed, so it describes what is on
	/// disk.
	fn finish(self, outcome: Result<(), StoreError>) -> Result<(), StoreError> {
		let committed = self.commit();
		outcome.and(committed)
	}

	/// Write the index, with the counter moved when something changed.
	fn commit(mut self) -> Result<(), StoreError> {
		self.commit_in_place()
	}

	/// As [`Self::commit`], keeping the transaction (and its lock) so the
	/// caller can read the counter it wrote.
	fn commit_in_place(&mut self) -> Result<(), StoreError> {
		if self.changed {
			self.index.state += 1;
			self.changed = false;
			self.index.save(&self.path).map_err(|_| StoreError::Io)?;
		}
		Ok(())
	}
}

#[path = "store_by_id.rs"]
mod by_id;
pub use super::store_check::Validated;
#[cfg(test)]
pub(crate) use super::store_check::counted;
pub use by_id::Tx;

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "store_tests_limits.rs"]
mod limits_tests;

#[cfg(test)]
#[path = "store_tests_check.rs"]
mod check_tests;

#[cfg(test)]
#[path = "store_tests_index.rs"]
mod index_tests;

#[cfg(test)]
#[path = "store_tests_by_id.rs"]
mod by_id_tests;

#[cfg(test)]
#[path = "store_tests_names.rs"]
mod names_tests;

#[cfg(test)]
#[path = "store_tests_tx.rs"]
mod tx_tests;

#[cfg(test)]
#[path = "store_tests_async.rs"]
mod async_tests;
