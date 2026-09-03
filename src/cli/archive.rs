//! `epistle archive`: inspect and operate on the per-account expunged-message
//! archive (`<account>/.archive/`), enabled by `[storage] deleted_retention_days`.
//!
//! The archive is opt-in: when the operator has not set a positive retention
//! window, the directory does not exist and every command exits with a
//! not-enabled error.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::config::Config;
use crate::imap::archive::{self, ArchivedMessage};

use super::util::message_crypto;

/// Subcommands on the archive.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
	/// List every archived message for an account (id, mailbox, unix time).
	List {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account whose archive to list.
		#[arg(value_name = "ACCOUNT")]
		account: String,
	},
	/// Restore an archived message to its original mailbox (or INBOX when that
	/// mailbox no longer exists). The restored message is appended as a new
	/// message with a fresh UID; the original `.eml` is removed from the
	/// archive.
	Restore {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account the archived message belongs to.
		#[arg(value_name = "ACCOUNT")]
		account: String,
		/// The archived message id (UUID).
		#[arg(value_name = "ID")]
		id: Uuid,
	},
	/// Delete archived entries. Without `--older-than-days`, every archived
	/// entry for the account is purged.
	Purge {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account whose archive to purge.
		#[arg(value_name = "ACCOUNT")]
		account: String,
		/// Only purge entries older than N days. Without this flag, every
		/// entry is purged. The sweep uses the same threshold.
		#[arg(long, value_name = "DAYS")]
		older_than_days: Option<u64>,
	},
}

/// Dispatch a parsed subcommand.
pub(super) fn dispatch(subcommand: Subcommand, out: &mut impl std::io::Write) -> ExitCode {
	match subcommand {
		Subcommand::List { config, account } => match Config::load(&config) {
			Ok(config) => match message_crypto(&config) {
				Ok(crypto) => list(&config.data_dir, &account, &crypto, out),
				Err(code) => code,
			},
			Err(error) => error_exit(error),
		},
		Subcommand::Restore {
			config,
			account,
			id,
		} => match Config::load(&config) {
			Ok(config) => match message_crypto(&config) {
				Ok(crypto) => restore(&config.data_dir, &account, id, &crypto, out),
				Err(code) => code,
			},
			Err(error) => error_exit(error),
		},
		Subcommand::Purge {
			config,
			account,
			older_than_days,
		} => match Config::load(&config) {
			Ok(config) => purge(&config.data_dir, &account, older_than_days, out),
			Err(error) => error_exit(error),
		},
	}
}

fn error_exit(error: impl std::fmt::Display) -> ExitCode {
	eprintln!("error: {error}");
	ExitCode::FAILURE
}

fn now_unix() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

fn list(
	data_dir: &Path,
	account: &str,
	_crypto: &crate::storage::MessageCrypto,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let account_root = data_dir.join("accounts").join(account);
	match archive::list(&account_root) {
		Ok(entries) => {
			render_entries(&entries, out);
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: listing archive: {error}");
			ExitCode::FAILURE
		}
	}
}

fn render_entries(entries: &[ArchivedMessage], out: &mut impl std::io::Write) {
	for entry in entries {
		let _ = writeln!(out, "{}\t{}\t{}", entry.id, entry.mailbox, entry.deleted_at);
	}
	let _ = writeln!(out, "{} archived", entries.len());
}

fn restore(
	data_dir: &Path,
	account: &str,
	id: Uuid,
	crypto: &crate::storage::MessageCrypto,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match archive::restore(data_dir, account, id, crypto) {
		Ok(target) => {
			let _ = writeln!(out, "restored {id} to {target}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: restoring archive entry: {error}");
			ExitCode::FAILURE
		}
	}
}

fn purge(
	data_dir: &Path,
	account: &str,
	older_than_days: Option<u64>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let account_root = data_dir.join("accounts").join(account);
	let older_than_secs = older_than_days
		.map(|days| days.saturating_mul(86_400))
		.unwrap_or(0);
	let now = now_unix();
	// The archive module's `purge` skips entries newer than `older_than_secs`;
	// the default (`0`) matches "older than zero seconds", which is every
	// entry.
	let threshold = if older_than_secs == 0 {
		0
	} else {
		older_than_secs.saturating_sub(1)
	};
	match archive::purge(&account_root, threshold, now) {
		Ok(removed) => {
			let _ = writeln!(out, "purged {removed} archived entries");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: purging archive: {error}");
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
