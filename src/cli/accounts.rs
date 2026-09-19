//! `mail accounts`: list the configured mail accounts from the command line.

use std::process::ExitCode;
use std::sync::Arc;

use crate::config::Config;
use crate::directory_store::removal::{QueuePolicy, remove_account};
use crate::directory_store::{AccountStore, DynamicAccount, StoreError};
use crate::storage::{FsSpool, MessageCrypto};

/// List every account (static config + dynamic store) with its addresses and
/// source. Writes to `out` so the formatting is unit-testable.
pub(super) fn list(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening account store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let mut views = store.account_views();
	views.sort_by(|a, b| a.0.cmp(&b.0));
	for (name, addresses, dynamic) in &views {
		let source = if *dynamic { "dynamic" } else { "static" };
		let _ = writeln!(out, "{name}\t{source}\t{}", addresses.join(","));
	}
	let _ = writeln!(out, "{} accounts", views.len());
	ExitCode::SUCCESS
}

/// Create a dynamic account with `addresses`, reading the password from
/// `reader` (one line) and hashing it (argon2id + SCRAM). `reader` is
/// injectable so the whole flow is testable.
pub(super) fn add(
	config: &Config,
	name: &str,
	addresses: Vec<String>,
	reader: impl std::io::BufRead,
) -> ExitCode {
	// let-else, not `match`: a match arm that returns is still an arm of the
	// expression whose value binds to `password`, and the taint analyser follows
	// that edge - rust/hard-coded-cryptographic-value reported the exit code in
	// the Err arm as a password reaching `validate(&password)`. An else block has
	// to diverge, so no value can travel from it to the binding.
	let Ok(password) = super::read_line(reader) else {
		return ExitCode::FAILURE;
	};
	if let Err(rejection) = crate::password::validate(&password) {
		super::style::error(rejection.message());
		return ExitCode::FAILURE;
	}
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening account store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let account = match DynamicAccount::with_password(name.to_string(), addresses, &password) {
		Ok(account) => account,
		Err(error) => {
			super::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	match store.add(account) {
		Ok(()) => {
			println!("created account {name}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// Parse a `--queue discard|drain` argument for `account-remove`. The
/// `value_parser` runs before the command runs so a typo never reaches
/// the removal flow.
pub(super) fn parse_queue_policy(value: &str) -> Result<QueuePolicy, String> {
	match value {
		"discard" => Ok(QueuePolicy::Discard),
		"drain" => Ok(QueuePolicy::Drain),
		other => Err(format!(
			"unknown queue policy \"{other}\" (expected discard or drain)"
		)),
	}
}

/// Remove a dynamic account and its whole footprint (mailbox, masked
/// addresses, app passwords, per-account suppression, queued outbound
/// mail per `queue`). Prints the per-record counts to `out`, one per
/// line, on success. Errors short-circuit; a missing account is `exit 1`
/// with a helpful message and no side effects. Spins up a short-lived
/// runtime because `remove_account` is async (it consults the optional
/// Bayesian store via sqlx).
pub(super) fn remove(
	config: &Config,
	name: &str,
	queue: QueuePolicy,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// Open without crypto: the removal path doesn't need to read message
	// bodies, and `remove_account` uses the spool itself for the queue
	// decision. Keeping crypto disabled avoids a misconfigured `[storage]`
	// path blocking legitimate cleanups.
	let _ = MessageCrypto::disabled();
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => Arc::new(store),
		Err(error) => {
			super::style::error(format_args!("opening account store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let spool = match FsSpool::open(&config.data_dir) {
		Ok(spool) => spool,
		Err(error) => {
			super::style::error(format_args!("opening spool: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("error: cannot start async runtime: {error}");
			return ExitCode::FAILURE;
		}
	};
	let result = runtime.block_on(remove_account(
		&store,
		&spool,
		&config.data_dir,
		name,
		queue,
		None,
	));
	match result {
		Ok(counts) => {
			let _ = writeln!(out, "removed account {name}");
			let _ = writeln!(out, "mailbox_files: {}", counts.mailbox_files);
			let _ = writeln!(out, "masked_addresses: {}", counts.masked_addresses);
			let _ = writeln!(out, "app_passwords: {}", counts.app_passwords);
			let _ = writeln!(out, "suppressed_addresses: {}", counts.suppressed_addresses);
			let _ = writeln!(
				out,
				"queued_messages_discarded: {}",
				counts.queued_messages_discarded
			);
			let _ = writeln!(out, "queued_messages_left: {}", counts.queued_messages_left);
			let _ = writeln!(out, "bayes_tokens_removed: {}", counts.bayes_tokens_removed);
			ExitCode::SUCCESS
		}
		Err(StoreError::NotFound(what)) => {
			super::style::error(format_args!("no such dynamic account: {what}"));
			ExitCode::FAILURE
		}
		Err(StoreError::Invalid(message)) => {
			super::style::error(message);
			ExitCode::FAILURE
		}
		Err(error @ StoreError::BayesPurge { .. }) => {
			super::style::error(format_args!(
				"bayes corpus purge failed for {name}; account retained, retry the removal once the database is reachable"
			));
			super::style::error(error);
			ExitCode::FAILURE
		}
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}
