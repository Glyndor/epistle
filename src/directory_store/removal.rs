//! Remove an account and every dependent record on disk.
//!
//! `AccountStore::remove` (in `mod.rs`) only drops the dynamic-account
//! row from `accounts.toml` and rebuilds the in-memory directory. What
//! it leaves behind depends on the path the deletion follows:
//!
//! - the mailbox directory at `<data_dir>/accounts/<name>/` (INBOX
//!   `new/`, `folders/`, `.archive/`, `dav/`, `tmp/`);
//! - the ManageSieve scripts under the same directory;
//! - masked addresses owned by the account;
//! - app passwords on the account;
//! - the per-account suppression list;
//! - queued outbound mail whose `reverse_path` is one of the account's
//!   addresses.
//!
//! The third class is the dangerous one: recreating the same name
//! inherits the previous user's mailbox. A data leak through an
//! ordinary admin operation.
//!
//! [`remove_account`] is the single entry point: it walks the footprint
//! in a deliberate order, validates `name` the same way the store
//! validates new names, refuses to follow symlinks, and reports a
//! per-record tally the audit log and the API response can render.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::AccountStore;
use super::StoreError;
use super::names::validate_name;
use crate::queue::SuppressionList;
use crate::storage::{CorrespondentStore, FsSpool};

/// What to do with the account's queued outbound mail when it is removed.
///
/// Discarding is opt-in only: the queue holds mail the user already
/// entrusted to the server, and dropping it silently is the worse
/// default. SCIM has no place for an explicit choice, so it passes
/// [`QueuePolicy::Drain`]; the management API requires the parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueuePolicy {
	/// Drop every queued message whose `reverse_path` belongs to the
	/// account. Spool files are removed; downstream retries do not see
	/// them again.
	Discard,
	/// Leave the queued messages alone. They will be delivered under
	/// whatever address they carry; the bounce address for a recipient
	/// will be wrong (the account no longer exists), but the message
	/// itself is preserved until delivery gives up on it.
	Drain,
}

/// Per-record tallies from a [`remove_account`] call, for the audit
/// event and the API response. Every field is `Default`-derived so a
/// caller that bails out before a step still has zero counts to render.
#[derive(Debug, Default, Serialize)]
pub struct Removed {
	/// Number of files inside the account's mailbox directory that
	/// were removed (recursive count, including the directory itself
	/// and every regular file inside).
	pub mailbox_files: u64,
	/// Number of masked-address entries removed.
	pub masked_addresses: u32,
	/// Number of app passwords removed.
	pub app_passwords: u32,
	/// Number of per-account suppression entries removed.
	pub suppressed_addresses: u32,
	/// Number of correspondent markers removed. Tracks who the account
	/// has previously written to; clearing the markers is part of the
	/// account-removal footprint so a re-created account does not
	/// inherit yesterday's recipient list and slip the daily new-cap.
	pub correspondent_addresses: u32,
	/// Queued messages dropped because the queue policy was
	/// [`QueuePolicy::Discard`].
	pub queued_messages_discarded: u32,
	/// Queued messages left untouched because the queue policy was
	/// [`QueuePolicy::Drain`].
	pub queued_messages_left: u32,
}

/// The full filesystem path to an account's mailbox root. Centralised so
/// the same path shape used by [`crate::imap::mailbox::mailbox_dir`] and
/// [`crate::managesieve::store::ScriptStore`] is used here too.
fn account_root(data_dir: &Path, name: &str) -> PathBuf {
	data_dir.join("accounts").join(name)
}

/// Remove every file inside an account's mailbox directory. Returns the
/// number of entries visited, including the directory itself; returns
/// `Ok(0)` when the directory does not exist (a freshly provisioned
/// account that has never received mail has nothing to remove).
///
/// Refuses to follow a symlink: `std::fs::remove_dir_all` does not
/// follow the top-level entry's symlink itself, but a `Meta` with
/// `file_type().is_symlink()` would let a stray symlink escape; the
/// `symlink_metadata` check rejects it before the recursive walk.
fn remove_mailbox_dir(root: &Path) -> std::io::Result<u64> {
	match fs::symlink_metadata(root) {
		Ok(meta) => {
			if meta.file_type().is_symlink() {
				return Err(std::io::Error::new(
					ErrorKind::InvalidInput,
					"refusing to follow a symlink at the account root",
				));
			}
			if !meta.is_dir() {
				return Err(std::io::Error::new(
					ErrorKind::InvalidInput,
					"account root is not a directory",
				));
			}
		}
		Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
		Err(error) => return Err(error),
	}
	let mut visited = 0u64;
	walk_and_remove(root, &mut visited)?;
	Ok(visited + 1)
}

/// Recursive remove that counts every entry (files, subdirectories, the
/// root). We walk first to keep the count independent of whether the
/// directory is empty when we get there.
fn walk_and_remove(dir: &Path, visited: &mut u64) -> std::io::Result<()> {
	for entry in fs::read_dir(dir)?.flatten() {
		let path = entry.path();
		let meta = fs::symlink_metadata(&path)?;
		if meta.file_type().is_symlink() {
			fs::remove_file(&path)?;
			*visited += 1;
			continue;
		}
		if meta.is_dir() {
			walk_and_remove(&path, visited)?;
			fs::remove_dir(&path)?;
		} else {
			fs::remove_file(&path)?;
		}
		*visited += 1;
	}
	Ok(())
}

/// Walk the spool, decide which envelopes belong to the account's
/// addresses, and either drop them or count them as left behind. The
/// decision on each envelope is the inverse of the policy: `Discard`
/// removes matching envelopes, `Drain` leaves them. Either way, the
/// mismatched (other-account) envelopes are untouched.
///
/// `addresses` is the case-insensitive set of `user@domain` strings
/// the removed account owned, pre-collected by the caller so the
/// membership test stays O(1) per envelope.
fn process_spool_queue(
	spool: &FsSpool,
	addresses: &[String],
	policy: QueuePolicy,
) -> std::io::Result<(u32, u32)> {
	let addresses: Vec<String> = addresses.iter().map(|a| a.to_ascii_lowercase()).collect();
	let mut discarded = 0u32;
	let mut left = 0u32;
	for id in spool.list()? {
		let entry = match spool.load(id) {
			Ok(entry) => entry,
			Err(_) => continue, // A corrupt envelope is not the removal caller's problem.
		};
		let matches = addresses
			.iter()
			.any(|address| entry.envelope.reverse_path.eq_ignore_ascii_case(address));
		match (matches, policy) {
			(true, QueuePolicy::Discard) => {
				spool.remove(id)?;
				discarded += 1;
			}
			(true, QueuePolicy::Drain) => left += 1,
			(false, _) => {}
		}
	}
	Ok((discarded, left))
}

/// Remove `name` and its whole footprint on disk.
///
/// Order matters and is encoded here:
///
/// 1. Validate `name` with the same rule [`AccountStore`] uses for new
///    accounts, so a malformed name never reaches the filesystem.
/// 2. Resolve `name` to its full set of addresses from the store's view
///    *before* `store.remove` runs: once the row is gone the addresses
///    are no longer reachable.
/// 3. Walk the spool and act on the queue, using those addresses. Doing
///    this first means a crash after the spool walk but before the
///    directory removal leaves the queued messages either already
///    discarded (matching the policy) or still there (matching the
///    policy), and the directory row still present so a follow-up
///    retry is straightforward.
/// 4. Drop the satellites (masked addresses, app passwords, per-account
///    suppression entries).
/// 5. Recursively remove the mailbox directory at
///    `<data_dir>/accounts/<name>`.
/// 6. Finally call `store.remove` so the directory row is the last
///    thing the on-disk state loses. A crash mid-flight therefore
///    leaves an account that still exists and can be re-removed, never
///    a ghost with data on disk.
pub fn remove_account(
	store: &AccountStore,
	spool: &FsSpool,
	data_dir: &Path,
	name: &str,
	queue: QueuePolicy,
) -> Result<Removed, StoreError> {
	validate_name(name)?;
	if store.dynamic(name).is_none() {
		return Err(StoreError::NotFound(name.to_string()));
	}
	let addresses: Vec<String> = store
		.dynamic(name)
		.map(|account| account.addresses)
		.unwrap_or_default();

	let (queued_messages_discarded, queued_messages_left) =
		process_spool_queue(spool, &addresses, queue).map_err(StoreError::Io)?;

	let masked_addresses = store.remove_all_masked(name)?;

	let app_passwords = store.remove_all_app_passwords(name)?;

	let suppression = SuppressionList::open(data_dir).map_err(StoreError::Io)?;
	let suppressed_addresses = suppression.remove_all_for(name).map_err(StoreError::Io)?;

	let correspondents = CorrespondentStore::open(data_dir).map_err(StoreError::Io)?;
	let correspondent_addresses = correspondents
		.remove_all_for(name)
		.map_err(StoreError::Io)?;

	let mailbox_root = account_root(data_dir, name);
	let mailbox_files = remove_mailbox_dir(&mailbox_root).map_err(StoreError::Io)?;

	store.remove(name)?;

	Ok(Removed {
		mailbox_files,
		masked_addresses,
		app_passwords,
		suppressed_addresses,
		correspondent_addresses,
		queued_messages_discarded,
		queued_messages_left,
	})
}

#[cfg(test)]
#[path = "removal_tests.rs"]
mod tests;
