//! Per-account Sieve script storage for ManageSieve (RFC 5804).
//!
//! Scripts live at `<data_dir>/accounts/<account>/sieve/<name>.sieve`. The
//! active script's name is recorded in `sieve/.active`, and its content is
//! mirrored to `<account>/filter.sieve` — the path the delivery pipeline reads
//! — so activating a script through ManageSieve takes effect immediately.

use std::fs;
use std::path::{Path, PathBuf};

use crate::util::path_component::AccountName;
use crate::util::path_containment::{contained, contained_child, contained_subdir};

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
		contained_child(&self.dirs()?.sieve_dir, &format!("{name}.sieve"))
			.map_err(|_| StoreError::InvalidName)
	}

	/// Parse `script` as Sieve, returning a human-readable reason on failure.
	pub fn validate(script: &str) -> Result<(), StoreError> {
		let tokens = crate::sieve::lexer::tokenize(script)
			.map_err(|error| StoreError::InvalidScript(format!("{error:?}")))?;
		let commands = crate::sieve::parser::parse(&tokens)
			.map_err(|error| StoreError::InvalidScript(format!("{error:?}")))?;
		enforce_mailbox_require(&commands)?;
		Ok(())
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

/// Walk a parsed script and reject it if it uses a feature of the
/// `mailbox` extension (RFC 5490) without first declaring it. The
/// `mailboxexists` test and the `:create` tag of `fileinto` only exist
/// when the extension is required, so a script that names them without
/// `require "mailbox"` cannot run anywhere it is uploaded; refusing it
/// here keeps the on-disk filter honest.
fn enforce_mailbox_require(commands: &[crate::sieve::ast::Command]) -> Result<(), StoreError> {
	if !uses_mailbox_feature(commands) {
		return Ok(());
	}
	if declares_mailbox_require(commands) {
		return Ok(());
	}
	Err(StoreError::InvalidScript(
		"mailboxexists or fileinto :create requires `require \"mailbox\"`".into(),
	))
}

/// Whether the script uses any of the `mailbox` extension's features.
fn uses_mailbox_feature(commands: &[crate::sieve::ast::Command]) -> bool {
	fn in_command(command: &crate::sieve::ast::Command) -> bool {
		match command {
			crate::sieve::ast::Command::Action { name, args } => {
				if name == "fileinto" {
					// `fileinto :create` only exists with the extension.
					if args.iter().any(
						|arg| matches!(arg, crate::sieve::ast::Argument::Tag(t) if t == "create"),
					) {
						return true;
					}
				}
				false
			}
			crate::sieve::ast::Command::If(conditional) => {
				in_test(&conditional.branches[0].test)
					|| conditional.branches.iter().any(|b| in_test(&b.test))
					|| conditional
						.branches
						.iter()
						.any(|b| b.body.iter().any(in_command))
					|| conditional
						.otherwise
						.as_ref()
						.is_some_and(|body| body.iter().any(in_command))
			}
		}
	}
	fn in_test(test: &crate::sieve::ast::Test) -> bool {
		if test.name == "mailboxexists" {
			return true;
		}
		test.children.iter().any(in_test)
	}
	commands.iter().any(in_command)
}

/// Whether the script has a `require "mailbox"` (or a list including
/// `"mailbox"`) anywhere in its top-level commands. Per RFC 5228 §3.3
/// the `require` must precede the first use, but for the validator's
/// purpose the presence anywhere in the script is enough; a client
/// that splits `require` from the action is malformed Sieve anyway.
fn declares_mailbox_require(commands: &[crate::sieve::ast::Command]) -> bool {
	use crate::sieve::ast::{Argument, Command};
	fn arg_names(arg: &Argument) -> Vec<&str> {
		match arg {
			Argument::Str(name) => vec![name.as_str()],
			Argument::StrList(list) => list.iter().map(String::as_str).collect(),
			_ => Vec::new(),
		}
	}
	commands.iter().any(|command| match command {
		Command::Action { name, args } => {
			name == "require" && args.iter().flat_map(arg_names).any(|s| s == "mailbox")
		}
		Command::If(_) => false,
	})
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
