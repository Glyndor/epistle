//! `epistle migrate imap`: copy every folder of a remote IMAP account into
//! a local account, resumably.
//!
//! The run logs in, lists the folders, maps each to a local mailbox (see
//! [`folders`]), and copies each folder in batches (see [`copy`]). Progress
//! is kept per local account, source and remote folder (see [`state`]), so
//! a second run copies only messages that arrived since, and a run that
//! stopped halfway resumes where it stopped.

mod client;
mod copy;
mod dedupe;
mod durability;
mod folders;
mod insecure;
mod ledger;
mod metadata;
mod parse;
mod state;
mod state_files;
mod token;
mod transport;
mod wire;

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroizing;

pub(crate) use client::ClientError;
pub(crate) use folders::Filter;
pub(crate) use transport::{Endpoint, Security, Verify};
pub(crate) use wire::Limits;

use client::Client;
use state::StateDir;

/// The remote account.
pub(crate) struct Source {
	/// Where the server is and how to reach it.
	pub(crate) endpoint: Endpoint,
	/// The remote login name.
	pub(crate) user: String,
	/// The remote password. Never printed.
	pub(crate) password: Zeroizing<String>,
}

/// The local account the mail goes into.
pub(crate) struct Target {
	/// The server's data directory.
	pub(crate) data_dir: PathBuf,
	/// The local account name.
	pub(crate) account: String,
	/// At-rest encryption for stored messages.
	pub(crate) crypto: crate::storage::MessageCrypto,
	/// The account's quota in bytes, `None` for no limit.
	pub(crate) quota: Option<u64>,
	/// Bytes the account already stores; grows as messages are copied.
	pub(crate) usage: u64,
	/// Maximum decoded size of an existing local message during recovery.
	pub(crate) max_message_size: usize,
}

/// How the copy runs.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
	/// Which folders are copied.
	pub(crate) filter: Filter,
	/// List what would be copied and change nothing.
	pub(crate) dry_run: bool,
	/// Bounds on every server response.
	pub(crate) limits: Limits,
	/// Most messages fetched in one command.
	pub(crate) batch_messages: usize,
	/// Most octets fetched in one command (one larger message still goes).
	pub(crate) batch_bytes: u64,
	/// Total time allowed for one resumable migration run.
	pub(crate) total_timeout: Duration,
}

impl Settings {
	/// The defaults: 64 KiB lines, literals up to the largest message the
	/// server accepts, 60 s without data, 10 minutes per command, 24 hours per run, batches of
	/// 100 messages or 32 MiB.
	pub(crate) fn new(filter: Filter, dry_run: bool) -> Self {
		Settings {
			filter,
			dry_run,
			limits: Limits {
				line: 64 * 1024,
				literal: crate::imap::command::DEFAULT_APPEND_LIMIT,
				idle: Duration::from_secs(60),
				response: Duration::from_secs(600),
			},
			batch_messages: 100,
			batch_bytes: 32 * 1024 * 1024,
			total_timeout: Duration::from_secs(24 * 60 * 60),
		}
	}
}

/// What happened to one folder.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct FolderReport {
	/// The remote folder.
	pub(crate) remote: String,
	/// The local mailbox.
	pub(crate) local: String,
	/// Messages the source listed for this run, confirmed ones included.
	pub(crate) messages: u64,
	/// Their total size as the server reported it.
	pub(crate) planned_bytes: u64,
	/// Messages stored.
	pub(crate) copied: u64,
	/// Octets stored.
	pub(crate) bytes: u64,
	/// Messages marked `\Deleted` remotely, not carried over.
	pub(crate) deleted: u64,
	/// Messages already stored locally, not stored again.
	pub(crate) duplicates: u64,
	/// Messages an earlier run already confirmed for this folder, not
	/// downloaded again.
	pub(crate) confirmed: u64,
	/// Messages over the local size limit, not carried over.
	pub(crate) too_large: u64,
	/// Messages that disappeared between listing and fetching.
	pub(crate) vanished: u64,
	/// The remote UIDVALIDITY changed, so the folder was copied again with
	/// duplicate checks.
	pub(crate) restarted: bool,
	/// Seconds spent on the folder.
	pub(crate) seconds: f64,
}

impl FolderReport {
	fn new(remote: &str, local: &str) -> Self {
		FolderReport {
			remote: remote.to_string(),
			local: local.to_string(),
			..FolderReport::default()
		}
	}
}

/// A folder that was not copied, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Skipped {
	/// The remote folder.
	pub(crate) folder: String,
	/// Why.
	pub(crate) reason: String,
}

/// The outcome of a run.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct Summary {
	/// Nothing was changed.
	pub(crate) dry_run: bool,
	/// Each folder handled.
	pub(crate) folders: Vec<FolderReport>,
	/// Each folder left out.
	pub(crate) skipped: Vec<Skipped>,
	/// Messages stored in total.
	pub(crate) copied: u64,
	/// Octets stored in total.
	pub(crate) bytes: u64,
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MigrateError {
	/// Talking to the server failed.
	#[error(transparent)]
	Client(#[from] ClientError),
	/// The next message would exceed the account's quota.
	#[error(
		"account {account} would exceed its quota: {usage} of {limit} bytes used, the next message needs {needed}; raise the quota (epistle account quota) and run again to continue"
	)]
	Quota {
		/// The local account.
		account: String,
		/// The quota.
		limit: u64,
		/// Bytes stored.
		usage: u64,
		/// Size of the message that did not fit.
		needed: u64,
	},
	/// Storing a message failed.
	#[error("storing mail: {0}")]
	Storage(std::io::Error),
	/// The migration reached its total time allowance.
	#[error(
		"IMAP migration total deadline exceeded; saved progress is retained, run again to resume"
	)]
	Timeout,
	/// Reading or writing the progress files failed.
	#[error("migration state: {0}")]
	State(std::io::Error),
}

/// Live progress of a run, for the terminal.
pub(crate) trait Progress {
	/// Copying of a folder starts.
	fn folder_start(&mut self, report: &FolderReport);
	/// A batch of the folder was stored.
	fn folder_progress(&mut self, report: &FolderReport);
	/// The folder is finished.
	fn folder_done(&mut self, report: &FolderReport);
	/// A folder is left out.
	fn skipped(&mut self, skipped: &Skipped);
}

/// Copy `source` into `target`. Returns what was done, and the error that
/// stopped the run early, if one did; the summary is valid either way.
pub(crate) async fn run(
	source: &Source,
	target: &mut Target,
	settings: &Settings,
	progress: &mut dyn Progress,
) -> (Summary, Option<MigrateError>) {
	run_with_connection(
		source,
		target,
		settings,
		progress,
		Client::connect(&source.endpoint, settings.limits),
	)
	.await
}

async fn run_with_connection(
	source: &Source,
	target: &mut Target,
	settings: &Settings,
	progress: &mut dyn Progress,
	connection: impl std::future::Future<Output = Result<Client, ClientError>>,
) -> (Summary, Option<MigrateError>) {
	let mut summary = Summary {
		dry_run: settings.dry_run,
		..Summary::default()
	};
	let error = match tokio::time::timeout(
		settings.total_timeout,
		copy_all(source, target, settings, progress, &mut summary, connection),
	)
	.await
	{
		Ok(result) => result.err(),
		Err(_) => Some(MigrateError::Timeout),
	};
	summary.copied = summary.folders.iter().map(|f| f.copied).sum();
	summary.bytes = summary.folders.iter().map(|f| f.bytes).sum();
	(summary, error)
}

async fn copy_all(
	source: &Source,
	target: &mut Target,
	settings: &Settings,
	progress: &mut dyn Progress,
	summary: &mut Summary,
	connection: impl std::future::Future<Output = Result<Client, ClientError>>,
) -> Result<(), MigrateError> {
	let mut client = connection.await?;
	client.login(&source.user, &source.password).await?;
	let namespace = client.namespace().await?;
	let entries = client.list().await?;
	let plans = folders::plan(&entries, namespace.as_deref(), &settings.filter);
	// The port is left out on purpose: the same account reached over 993
	// one day and STARTTLS on 143 the next is still the same mail.
	let key = format!(
		"{}@{}",
		source.user,
		source.endpoint.host.to_ascii_lowercase()
	);
	let states =
		StateDir::open(&target.data_dir, &target.account, &key).map_err(MigrateError::State)?;
	for plan in &plans {
		let local = match &plan.local {
			Ok(local) => local,
			Err(reason) => {
				let skipped = Skipped {
					folder: plan.display.clone(),
					reason: reason.to_string(),
				};
				progress.skipped(&skipped);
				summary.skipped.push(skipped);
				continue;
			}
		};
		summary
			.folders
			.push(FolderReport::new(&plan.display, local));
		let report = summary.folders.last_mut().expect("current folder");
		let copied = copy::folder(
			&mut client,
			plan,
			report,
			&states,
			target,
			settings,
			progress,
		)
		.await;
		match copied {
			Ok(()) => {
				progress.folder_done(report);
			}
			// The folder went away or cannot be opened: report it, go on.
			Err(MigrateError::Client(ClientError::Refused { text, .. })) => {
				summary.folders.pop();
				let skipped = Skipped {
					folder: plan.display.clone(),
					reason: format!("the server refused to open it: {text}"),
				};
				progress.skipped(&skipped);
				summary.skipped.push(skipped);
			}
			Err(error) => {
				// What was stored before the stop is part of the summary.
				if report.copied == 0 {
					summary.folders.pop();
				}
				return Err(error);
			}
		}
	}
	client.logout().await;
	Ok(())
}

#[cfg(test)]
#[path = "fake_server.rs"]
mod fake_server;

#[cfg(test)]
#[path = "run_tests.rs"]
mod run_tests;

#[cfg(test)]
#[path = "run_tests_security.rs"]
mod run_tests_security;

#[cfg(test)]
#[path = "run_tests_memory.rs"]
mod run_tests_memory;

#[cfg(test)]
#[path = "ledger_resume_tests.rs"]
mod ledger_resume_tests;
