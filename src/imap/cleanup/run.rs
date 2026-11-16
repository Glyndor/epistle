//! One cleanup run over every account.

use std::path::Path;

use super::{Policy, Prefs, combine, cursor, folder_keys};
use crate::imap::mailbox::{self, MessageRef, Snapshot};
use crate::imap::special_use::Roles;
use crate::storage::MessageCrypto;
use crate::util::path_component::AccountName;
use crate::util::path_containment::contained;

/// Whether a run removes what is due or only counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
	/// Remove at most [`Policy::max_per_run`] messages and move the cursor.
	Apply,
	/// Remove nothing, move nothing, and count everything that is due.
	DryRun,
}

/// What is due in one folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
	/// The account.
	pub account: String,
	/// The mailbox.
	pub folder: String,
	/// The retention that made it due, in days.
	pub days: u64,
	/// Messages removed, or that a dry run would remove.
	pub messages: u64,
}

/// What a run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
	/// Folders with something due, in the order they were visited.
	pub folders: Vec<Counts>,
	/// Accounts looked at.
	pub accounts: u64,
	/// Whether the cap stopped the run before every account was visited.
	pub capped: bool,
}

impl Report {
	/// Messages removed (or that a dry run would remove).
	pub fn messages(&self) -> u64 {
		self.folders.iter().map(|folder| folder.messages).sum()
	}
}

/// Run the cleanup `policy` describes over `data_dir`, judging age by `now`
/// (epoch seconds). `retention_days` is `[storage] deleted_retention_days`:
/// when it is positive a removed message goes to the archive like an expunged
/// one.
///
/// The age of a message is the time it has been in its folder, the later of
/// its INTERNALDATE and the change time of its file. A COPY or MOVE carries
/// INTERNALDATE over, so a two-year-old message moved to Trash today has an
/// old INTERNALDATE and a change time of today, and stays. The change time is
/// the file system's and no client can set it back.
pub fn run(
	data_dir: &Path,
	policy: &Policy,
	retention_days: u64,
	now: u64,
	mode: Mode,
) -> std::io::Result<Report> {
	let mut report = Report::default();
	let mut budget = match mode {
		Mode::Apply => policy.max_per_run(),
		Mode::DryRun => usize::MAX,
	};
	let mut names = account_names(data_dir)?;
	names.sort();
	let start = match mode {
		Mode::Apply => cursor::read(data_dir),
		Mode::DryRun => None,
	};
	if let Some(start) = &start {
		names.retain(|name| name >= start);
	}
	for name in &names {
		report.accounts += 1;
		clean_account(
			data_dir,
			policy,
			retention_days,
			now,
			mode,
			name,
			&mut budget,
			&mut report,
		);
		if budget == 0 {
			report.capped = true;
			if mode == Mode::Apply {
				cursor::write(data_dir, Some(name))?;
			}
			return Ok(report);
		}
	}
	if mode == Mode::Apply {
		cursor::write(data_dir, None)?;
	}
	Ok(report)
}

fn account_names(data_dir: &Path) -> std::io::Result<Vec<String>> {
	let accounts = contained(data_dir, &data_dir.join("accounts"))?;
	let entries = match crate::util::fs_walk::read_dir(&accounts) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(error) => return Err(error),
	};
	Ok(entries
		.flatten()
		.filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
		.filter_map(|entry| entry.file_name().to_str().map(str::to_string))
		.filter(|name| AccountName::new(name).is_ok())
		.collect())
}

#[allow(clippy::too_many_arguments)]
fn clean_account(
	data_dir: &Path,
	policy: &Policy,
	retention_days: u64,
	now: u64,
	mode: Mode,
	account: &str,
	budget: &mut usize,
	report: &mut Report,
) {
	let subject = policy.subject(account);
	let roles = Roles::load(data_dir, account);
	let prefs = Prefs::load(data_dir, account);
	for folder in mailbox::list(data_dir, account) {
		if *budget == 0 {
			return;
		}
		if folder.eq_ignore_ascii_case("INBOX") {
			continue;
		}
		let keys = folder_keys(&folder, &roles);
		let days = combine(policy.operator_days(&subject, &keys), prefs.days_for(&keys));
		let Some(days) = days.filter(|days| *days > 0) else {
			continue;
		};
		let cutoff = now.saturating_sub(days.saturating_mul(86_400));
		match clean_folder(
			data_dir,
			account,
			&folder,
			retention_days,
			now,
			cutoff,
			mode,
			*budget,
		) {
			Ok(0) => {}
			Ok(messages) => {
				*budget = budget.saturating_sub(usize::try_from(messages).unwrap_or(usize::MAX));
				report.folders.push(Counts {
					account: account.to_string(),
					folder,
					days,
					messages,
				});
			}
			Err(error) => {
				tracing::warn!(kind = ?error.kind(), "cleanup could not process a folder");
			}
		}
	}
}

#[allow(clippy::too_many_arguments)]
fn clean_folder(
	data_dir: &Path,
	account: &str,
	folder: &str,
	retention_days: u64,
	now: u64,
	cutoff: u64,
	mode: Mode,
	budget: usize,
) -> std::io::Result<u64> {
	// Nothing is read from a body, so no key is needed.
	let mut snapshot = Snapshot::open_at(
		data_dir,
		account,
		folder,
		&MessageCrypto::disabled(),
		retention_days,
		now,
	)?;
	let due: Vec<u32> = snapshot
		.messages()
		.filter(|message| entered_before(&snapshot, message, cutoff))
		.map(|message| message.uid)
		.take(budget)
		.collect();
	if mode == Mode::Apply && !due.is_empty() {
		let removed = snapshot.remove_uids(&due)?;
		return Ok(removed.len() as u64);
	}
	Ok(due.len() as u64)
}

/// Whether the message came into its folder before `cutoff`.
fn entered_before(snapshot: &Snapshot, message: &MessageRef, cutoff: u64) -> bool {
	let internal = message
		.internal_date
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs());
	// It cannot have entered before its INTERNALDATE, so a recent one is
	// settled without touching the disk.
	if internal >= cutoff {
		return false;
	}
	let Ok(path) = snapshot.message_path(message) else {
		return false;
	};
	changed_at(&path).is_some_and(|changed| internal.max(changed) < cutoff)
}

/// The change time of a file, in epoch seconds. A file whose change time
/// cannot be read is not due: the cleanup never guesses.
#[cfg(unix)]
fn changed_at(path: &Path) -> Option<u64> {
	use std::os::unix::fs::MetadataExt;
	let metadata = std::fs::metadata(path).ok()?;
	u64::try_from(metadata.ctime()).ok()
}

#[cfg(not(unix))]
fn changed_at(_path: &Path) -> Option<u64> {
	None
}
