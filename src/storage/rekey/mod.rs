//! Re-encrypting stored mail under the key its account should use now.
//!
//! A run walks every account directory under `<data_dir>/accounts/` and
//! the account's blob partition under `<data_dir>/blobs/accounts/`, and
//! rewrites each envelope that is not under the account's target key:
//! its tenant's key going forward, the server key on a rollback or for an
//! account in no keyed tenant. Plaintext files are left as they are.
//!
//! Each file is replaced only after its new form is on disk and proven:
//! the new envelope goes to a temporary file beside the original, is
//! fsynced, read back from disk and opened, and only when it opens under
//! the target key to the same bytes does a rename put it in place. A cut
//! at any point leaves either the old file or the new one, both readable,
//! plus at most one temporary file that the next run removes. The file
//! name, permissions and modification time (the IMAP INTERNALDATE) are
//! kept, so nothing is duplicated and nothing is renumbered.

use std::path::{Path, PathBuf};

use crate::storage::{EnvelopeKind, KeyOwner, MessageCrypto, TenantChoice};

pub mod journal;

pub use journal::{Direction, Journal};

/// Suffix of the temporary file a rewrite writes before the rename.
pub const TEMP_SUFFIX: &str = ".rekey-tmp";

/// Points where a test can interrupt or corrupt a run. Production passes
/// [`NoHooks`].
pub trait Hooks {
	/// Called after the temporary file is written and before it is
	/// verified. An error aborts the run there.
	fn after_temp_write(&mut self, _temp: &Path) -> std::io::Result<()> {
		Ok(())
	}
	/// Called after verification and before the rename. An error aborts
	/// the run there, which is where a cut leaves a temporary file behind.
	fn before_replace(&mut self, _original: &Path) -> std::io::Result<()> {
		Ok(())
	}
}

/// The hooks a real run uses: none.
pub struct NoHooks;

impl Hooks for NoHooks {}

/// What happened to one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOutcome {
	/// It was already under the target key.
	Already,
	/// It carries no envelope.
	Plaintext,
	/// It would be rewritten (dry run).
	WouldRewrite,
	/// It was rewritten under the target key.
	Rewritten,
}

/// Counts for one account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
	/// Files rewritten, or that a dry run would rewrite.
	pub rewritten: u64,
	/// Files already under the target key.
	pub already: u64,
	/// Files with no envelope, left as they are.
	pub plaintext: u64,
}

impl Totals {
	fn add(&mut self, outcome: FileOutcome) {
		match outcome {
			FileOutcome::Already => self.already += 1,
			FileOutcome::Plaintext => self.plaintext += 1,
			FileOutcome::WouldRewrite | FileOutcome::Rewritten => self.rewritten += 1,
		}
	}
}

/// The key `account`'s mail should be under for a run in `direction`.
pub fn target_for(crypto: &MessageCrypto, account: &str, direction: Direction) -> KeyOwner {
	if direction == Direction::Rollback {
		return KeyOwner::Server;
	}
	match crypto.tenant_of_account(account) {
		TenantChoice::One(name) if crypto.has_key(&KeyOwner::Tenant(name.clone())) => {
			KeyOwner::Tenant(name)
		}
		_ => KeyOwner::Server,
	}
}

/// Every account with a directory under `<data_dir>/accounts/`, sorted.
pub fn accounts(data_dir: &Path) -> std::io::Result<Vec<String>> {
	let root = data_dir.join("accounts");
	let mut names = Vec::new();
	let entries = match std::fs::read_dir(&root) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(names),
		Err(error) => return Err(error),
	};
	for entry in entries {
		let entry = entry?;
		if entry.file_type()?.is_dir()
			&& let Ok(name) = entry.file_name().into_string()
			&& crate::util::path_component::AccountName::new(&name).is_ok()
		{
			names.push(name);
		}
	}
	names.sort();
	Ok(names)
}

/// The trees that hold `account`'s encrypted files.
fn roots(data_dir: &Path, account: &str) -> [PathBuf; 2] {
	[
		data_dir.join("accounts").join(account),
		data_dir.join("blobs").join("accounts").join(account),
	]
}

/// Re-encrypt every envelope of `account` under `target`. A dry run only
/// counts. Leftover temporary files from a cut run are removed first.
pub fn rekey_account(
	crypto: &MessageCrypto,
	data_dir: &Path,
	account: &str,
	target: &KeyOwner,
	dry_run: bool,
	hooks: &mut dyn Hooks,
) -> std::io::Result<Totals> {
	let mut totals = Totals::default();
	for root in roots(data_dir, account) {
		let mut files = Vec::new();
		collect(&root, &mut files)?;
		for file in files {
			if is_temp(&file) {
				if !dry_run {
					std::fs::remove_file(&file)?;
				}
				continue;
			}
			totals.add(rekey_file(crypto, &file, target, dry_run, hooks)?);
		}
	}
	Ok(totals)
}

fn is_temp(path: &Path) -> bool {
	path.file_name()
		.and_then(|name| name.to_str())
		.is_some_and(|name| name.ends_with(TEMP_SUFFIX))
}

/// Every regular file under `dir`, depth first. Symbolic links are not
/// followed: the store never writes one, and following one could rewrite
/// a file outside the account.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
	let entries = match std::fs::read_dir(dir) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
		Err(error) => return Err(error),
	};
	let mut sorted: Vec<_> = entries.collect::<Result<_, _>>()?;
	sorted.sort_by_key(|entry| entry.file_name());
	for entry in sorted {
		let kind = entry.file_type()?;
		if kind.is_dir() {
			collect(&entry.path(), out)?;
		} else if kind.is_file() {
			out.push(entry.path());
		}
	}
	Ok(())
}

/// Re-encrypt one file under `target`, verifying the new bytes on disk
/// before they replace the old ones.
///
/// # Errors
/// When the file cannot be read or opened (its key is not loaded, or it is
/// damaged), when the new envelope does not verify, or when a hook aborts.
/// The original is untouched in every one of those cases.
pub fn rekey_file(
	crypto: &MessageCrypto,
	path: &Path,
	target: &KeyOwner,
	dry_run: bool,
	hooks: &mut dyn Hooks,
) -> std::io::Result<FileOutcome> {
	let stored = std::fs::read(path)?;
	if crate::storage::envelope_kind(&stored) == EnvelopeKind::Plain {
		return Ok(FileOutcome::Plaintext);
	}
	let (plain, owner) = crypto
		.open_owned(&stored)
		.map_err(|error| std::io::Error::other(format!("{}: {error}", path.display())))?;
	if owner == *target {
		return Ok(FileOutcome::Already);
	}
	if dry_run {
		return Ok(FileOutcome::WouldRewrite);
	}
	let sealed = crypto.seal_for(target, &plain)?;
	let temp = temp_path(path)?;
	let modified = std::fs::metadata(path)?.modified()?;
	crate::storage::spool::write_sync(&temp, &sealed)?;
	std::fs::File::options()
		.write(true)
		.open(&temp)?
		.set_modified(modified)?;
	let result = hooks
		.after_temp_write(&temp)
		.and_then(|()| verify(crypto, &temp, &plain, target))
		.and_then(|()| hooks.before_replace(path));
	if let Err(error) = result {
		// A verification failure removes the temporary file; a hook abort
		// stands in for a crash and leaves it, as a crash would.
		if error.kind() == std::io::ErrorKind::InvalidData {
			let _ = std::fs::remove_file(&temp);
		}
		return Err(error);
	}
	std::fs::rename(&temp, path)?;
	if let Some(parent) = path.parent() {
		journal::sync_dir(parent)?;
	}
	Ok(FileOutcome::Rewritten)
}

/// The temporary file beside `path`.
fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
	let name = path
		.file_name()
		.and_then(|name| name.to_str())
		.ok_or_else(|| std::io::Error::other("a stored file name is not UTF-8"))?;
	Ok(path.with_file_name(format!(".{name}{TEMP_SUFFIX}")))
}

/// Read `temp` back from disk and require it to open under `target` to
/// exactly `plain`.
fn verify(
	crypto: &MessageCrypto,
	temp: &Path,
	plain: &[u8],
	target: &KeyOwner,
) -> std::io::Result<()> {
	let reread = std::fs::read(temp)?;
	match crypto.open_owned(&reread) {
		Ok((again, owner)) if again == plain && owner == *target => Ok(()),
		_ => Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			format!(
				"{}: the re-encrypted copy did not verify; the original is kept",
				temp.display()
			),
		)),
	}
}

#[cfg(test)]
pub(crate) mod tests;
