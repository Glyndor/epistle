//! Validated path components for everything that lives under the data
//! directory.
//!
//! Account names, mailbox names, message ids and digest file names reach the
//! filesystem as one path component each. Every such component is built here,
//! so the guarantee that it cannot escape its parent directory is local and
//! checked at the join instead of depending on whichever caller happened to
//! validate it first.
//!
//! * [`AccountName`] and [`MailboxName`] wrap client- or operator-supplied
//!   text and refuse anything that is not a single, plain directory name.
//! * [`DigestName`], [`MessageExt`] and [`StateFile`] cannot carry free text:
//!   the first is built from a SHA-256 digest, the others are closed sets of
//!   fixed names, and message ids are typed [`Uuid`]s.
//!
//! Validating a component is not the last line of defence. Every path built
//! here is also passed through [`contained`], which resolves it and refuses
//! it if it is not inside the directory it was joined onto, so a mistake in
//! one validator, or a symlink inside the tree, cannot take a join outside.

use std::fmt;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::mailbox_path;
use super::path_containment::{contained, contained_child, contained_subdir};

/// Longest account or mailbox name accepted (bytes). Well under the 255 byte
/// limit of common filesystems, leaving room for suffixes.
const MAX_COMPONENT_LEN: usize = 128;

/// A name was rejected because it cannot be used as one plain path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidComponent;

impl fmt::Display for InvalidComponent {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("invalid path component")
	}
}

impl std::error::Error for InvalidComponent {}

impl From<InvalidComponent> for std::io::Error {
	fn from(error: InvalidComponent) -> Self {
		std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
	}
}

/// Whether `name` is a single plain path component: not empty, not `.` or
/// `..`, no separator, no NUL or other control character, not absolute, and
/// not longer than `MAX_COMPONENT_LEN` bytes.
pub fn is_plain_component(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= MAX_COMPONENT_LEN
		&& name != "."
		&& name != ".."
		&& !name
			.chars()
			.any(|c| c.is_control() || matches!(c, '/' | '\\'))
		&& !Path::new(name).is_absolute()
}

/// The name of a mail account, validated as one directory name.
///
/// This is a path-safety rule, not the account-creation policy: any name that
/// is one plain path component is accepted, with its case kept. Directories
/// such as SQL and LDAP name accounts `john.doe` or `J_Smith`, and those
/// names map to a directory of the same name. What an operator may create
/// (lowercase letters, digits and `-`) is enforced where accounts are created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountName<'a>(&'a str);

impl<'a> AccountName<'a> {
	/// Validate `name` as an account directory name.
	pub fn new(name: &'a str) -> Result<Self, InvalidComponent> {
		if is_plain_component(name) {
			Ok(Self(name))
		} else {
			Err(InvalidComponent)
		}
	}

	/// The validated name.
	pub fn as_str(&self) -> &'a str {
		self.0
	}

	/// The account's root directory: `<data_dir>/accounts/<name>`, resolved
	/// and checked to lie inside `<data_dir>/accounts`.
	pub fn root(&self, data_dir: &Path) -> std::io::Result<AccountRoot> {
		let accounts = contained(data_dir, &data_dir.join("accounts"))?;
		contained_subdir(&accounts, self.0).map(AccountRoot)
	}

	/// An account name that skips validation, so tests can show that the
	/// containment check still refuses a path when a validator is wrong.
	#[cfg(test)]
	pub(crate) fn unchecked(name: &'a str) -> Self {
		Self(name)
	}
}

/// `<data_dir>/accounts/<name>` for a validated account. Only
/// [`AccountName::root`] builds one, so code that receives it does not have
/// to trust whoever joined the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRoot(PathBuf);

impl AccountRoot {
	/// A root that names no directory, for values that are never read from
	/// disk (a placeholder swapped in while a session re-opens a mailbox).
	pub fn placeholder() -> Self {
		Self(PathBuf::new())
	}

	/// The directory path.
	pub fn as_path(&self) -> &Path {
		&self.0
	}

	/// A file or directory directly under the account root, such as
	/// `filter.sieve` or `.vacation`. `name` must be one plain name.
	pub fn file(&self, name: &str) -> std::io::Result<PathBuf> {
		contained_child(&self.0, name)
	}

	/// The path of a child of the account root with a fixed, program-chosen
	/// name (`tmp`, `new`, `folders`, `.archive`, ...).
	pub fn child(&self, fixed: FixedDir) -> std::io::Result<PathBuf> {
		contained(&self.0, &self.0.join(fixed.name()))
	}
}

impl AsRef<Path> for AccountRoot {
	fn as_ref(&self) -> &Path {
		&self.0
	}
}

impl std::ops::Deref for AccountRoot {
	type Target = Path;

	fn deref(&self) -> &Path {
		&self.0
	}
}

/// Directories the server itself creates directly under an account root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedDir {
	/// Incoming INBOX messages.
	New,
	/// Staging area for crash-safe delivery.
	Tmp,
	/// Every non-inbox mailbox.
	Folders,
	/// Expunged messages kept for the retention window.
	Archive,
}

impl FixedDir {
	fn name(self) -> &'static str {
		match self {
			Self::New => "new",
			Self::Tmp => "tmp",
			Self::Folders => "folders",
			Self::Archive => ".archive",
		}
	}
}

/// A mailbox: `INBOX`, or a folder with a restricted, possibly hierarchical
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxName<'a> {
	/// The always-present inbox (matched case-insensitively).
	Inbox,
	/// A folder under `folders/`, by its stored name. Each level between `/`
	/// delimiters is ASCII letters, digits, space, `-`, `_` and `.`, plus
	/// non-ASCII characters spelled in modified UTF-7 (`Entw&APw-rfe` for
	/// `Entwürfe`, RFC 3501 §5.1.3); a level cannot be empty, start with a
	/// dot or end with a space. See [`super::mailbox_path`] for the limits
	/// and the on-disk spelling.
	Folder(&'a str),
}

impl<'a> MailboxName<'a> {
	/// Accept `INBOX` (any case) or a valid folder name.
	pub fn new(name: &'a str) -> Result<Self, InvalidComponent> {
		if name.eq_ignore_ascii_case("INBOX") {
			Ok(Self::Inbox)
		} else {
			Self::folder(name)
		}
	}

	/// Accept only a folder name; `INBOX` is refused. Used for create,
	/// delete and rename, which must never touch the inbox.
	pub fn folder(name: &'a str) -> Result<Self, InvalidComponent> {
		if mailbox_path::valid_folder(name) {
			Ok(Self::Folder(name))
		} else {
			Err(InvalidComponent)
		}
	}

	/// The directory holding the mailbox's messages: `<account_root>/new` for
	/// the inbox, `<account_root>/folders/<disk name>/new` for a folder.
	pub fn messages_dir(
		&self,
		account: &AccountName<'_>,
		data_dir: &Path,
	) -> std::io::Result<PathBuf> {
		let root = account.root(data_dir)?;
		match self {
			Self::Inbox => root.child(FixedDir::New),
			Self::Folder(name) => {
				let folders = root.child(FixedDir::Folders)?;
				let disk = mailbox_path::disk_name(name);
				contained_child(&contained_subdir(&folders, &disk)?, "new")
			}
		}
	}

	/// The folder's own directory (`<account_root>/folders/<disk name>`), or
	/// `None` for the inbox, which has no folder directory. The disk name is
	/// the stored name with `/` written as `&AC8-`, one path component.
	pub fn folder_dir(
		&self,
		account: &AccountName<'_>,
		data_dir: &Path,
	) -> std::io::Result<Option<PathBuf>> {
		match self {
			Self::Inbox => Ok(None),
			Self::Folder(name) => {
				let folders = folders_dir(account, data_dir)?;
				contained_subdir(&folders, &mailbox_path::disk_name(name)).map(Some)
			}
		}
	}
}

/// The `<account_root>/folders` directory that holds every non-inbox mailbox.
pub fn folders_dir(account: &AccountName<'_>, data_dir: &Path) -> std::io::Result<PathBuf> {
	account.root(data_dir)?.child(FixedDir::Folders)
}

/// A file name made only of the lowercase hex of a SHA-256 digest, so it can
/// never hold a separator or a dot. Used where free text (an address, an
/// account name) has to name a file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DigestName(String);

impl DigestName {
	/// A short, stable stand-in for `value` that is safe to log in place of the
	/// raw text (the first 12 hex digits of its digest).
	pub fn pseudonym(value: &str) -> String {
		Self::of(value).0.chars().take(12).collect()
	}

	/// Digest `value` after lowercasing it (ASCII), so lookups are
	/// case-insensitive.
	pub fn of(value: &str) -> Self {
		use std::fmt::Write;
		let digest =
			ring::digest::digest(&ring::digest::SHA256, value.to_ascii_lowercase().as_bytes());
		let hex = digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
			let _ = write!(acc, "{byte:02x}");
			acc
		});
		Self(hex)
	}

	/// `<dir>/<digest>`.
	pub fn in_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
		contained(dir, &dir.join(&self.0))
	}

	/// `<dir>/<digest>.lock`.
	pub fn lock_in_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
		contained(dir, &dir.join(format!("{}.lock", self.0)))
	}
}

impl fmt::Display for DigestName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

/// The per-message files that sit next to each other under one id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageExt {
	/// The message body.
	Eml,
	/// Flag sidecar.
	Flags,
	/// UID sidecar.
	Uid,
	/// Mod-sequence sidecar.
	Modseq,
	/// INTERNALDATE zone sidecar.
	Zone,
	/// Archive deletion record.
	Deleted,
	/// Spool envelope.
	Json,
}

impl MessageExt {
	fn suffix(self) -> &'static str {
		match self {
			Self::Eml => ".eml",
			Self::Flags => ".flags",
			Self::Uid => ".uid",
			Self::Modseq => ".modseq",
			Self::Zone => ".zone",
			Self::Deleted => ".deleted",
			Self::Json => ".json",
		}
	}
}

/// `<dir>/<id><ext>`.
pub fn message_file(dir: &Path, id: Uuid, ext: MessageExt) -> std::io::Result<PathBuf> {
	contained_child(dir, &format!("{id}{}", ext.suffix()))
}

/// `<dir>/<id><ext>.tmp`, the staging name used before an atomic rename.
pub fn message_tmp_file(dir: &Path, id: Uuid, ext: MessageExt) -> std::io::Result<PathBuf> {
	contained_child(dir, &format!("{id}{}.tmp", ext.suffix()))
}

/// The fixed per-mailbox (and, for the JMAP journal, per-account) bookkeeping
/// files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFile {
	/// Next UID counter.
	UidNext,
	/// UIDVALIDITY value.
	UidValidity,
	/// Per-account last UIDVALIDITY handed out to a new mailbox.
	UidValidityLast,
	/// Per-account lock serialising UIDVALIDITY allocation.
	UidValidityLock,
	/// Mod-sequence counter.
	ModseqCounter,
	/// Expunge log (QRESYNC).
	Vanished,
	/// Metadata index.
	Index,
	/// Per-account JMAP change journal (one line per changed object).
	JmapJournal,
	/// Per-account JMAP journal header: epoch and trim floor.
	JmapState,
	/// Per-account lock serialising every JMAP journal reader and writer.
	JmapLock,
}

impl StateFile {
	/// The file name inside the directory it belongs to.
	pub(crate) fn name(self) -> &'static str {
		match self {
			Self::UidNext => ".uidnext",
			Self::UidValidity => ".uidvalidity",
			Self::UidValidityLast => ".uidvalidity_last",
			Self::UidValidityLock => ".uidvalidity_lock",
			Self::ModseqCounter => ".modseqctr",
			Self::Vanished => ".vanished",
			Self::Index => ".index",
			Self::JmapJournal => ".jmap_changes",
			Self::JmapState => ".jmap_state",
			Self::JmapLock => ".jmap_lock",
		}
	}
}

/// `<dir>/<state file>`.
pub fn state_file(dir: &Path, file: StateFile) -> std::io::Result<PathBuf> {
	contained_child(dir, file.name())
}

/// `<dir>/<state file>.tmp`, the staging name used before an atomic rename.
pub fn state_tmp_file(dir: &Path, file: StateFile) -> std::io::Result<PathBuf> {
	contained_child(dir, &format!("{}.tmp", file.name()))
}

#[cfg(test)]
#[path = "path_component_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "path_component_tests_hierarchy.rs"]
mod tests_hierarchy;
