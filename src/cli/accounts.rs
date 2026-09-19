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

/// Open the optional Bayesian store the operator's `[database]`
/// section configures.
///
/// The decision is binary when `[database]` is set: either the pool
/// opens and we hand the bayes store to `remove_account`, or it does
/// not (the host is unreachable, the credentials are wrong, the
/// migrations did not run) and we refuse the removal. A recreated
/// account name would otherwise inherit the previous owner's
/// training rows, which is the silent leak the abort exists to
/// prevent: skipping the purge by accepting `connect_database`'s
/// `Ok(None)` answer was the exact regression the helper made
/// possible, so a `[database]` section is now a hard prerequisite for
/// the bayes work. With no `[database]` at all there is no corpus
/// to drop, so the caller proceeds without one.
///
/// Errors during the corpus-key file load (the only step `open_bayes`
/// does not silently absorb) are returned as `Err` so the caller can
/// route the failure through stderr (the standard `error:` decorator
/// the rest of the CLI uses); stdout is reserved for the count
/// summary.
fn open_bayes_store(
	config: &Config,
	runtime: &tokio::runtime::Runtime,
) -> Result<Option<crate::antispam::corpus::BayesStore>, String> {
	if config.database.is_none() {
		return Ok(None);
	}
	runtime.block_on(async {
		let metrics = Arc::new(crate::metrics::Metrics::new());
		let pool = match super::serve_tasks::connect_database(config, &metrics).await {
			Ok(Some(pool)) => pool,
			Ok(None) => {
				return Err(
					"the database holding the account's training could not be reached; \
					 the removal was not started and can be retried once the database is back"
						.to_string(),
				);
			}
			Err(error) => return Err(format!("opening database: {error}")),
		};
		match super::serve_tasks::open_bayes(
			config,
			&Some(pool),
			&MessageCrypto::disabled(),
			&metrics,
		) {
			Ok(Some((store, _queue))) => Ok(Some(store)),
			Ok(None) => Ok(None),
			Err(error) => Err(format!("opening bayes store: {error}")),
		}
	})
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
	let bayes_store = match open_bayes_store(config, &runtime) {
		Ok(store) => store,
		Err(message) => {
			super::style::error(format_args!("account {name}: {message}"));
			return ExitCode::FAILURE;
		}
	};
	remove_with_bayes(
		&runtime,
		&store,
		&spool,
		config,
		name,
		queue,
		bayes_store.as_ref(),
		out,
	)
}

/// Inner removal helper that the tests drive directly with a
/// hand-built [`BayesStore`]. The public [`remove`] opens the store
/// from the configuration; tests bypass `open_bayes_store` to feed
/// in a deterministic pool without touching the operator's
/// `[database]` URL.
#[allow(clippy::too_many_arguments)]
pub(super) fn remove_with_bayes(
	runtime: &tokio::runtime::Runtime,
	store: &Arc<AccountStore>,
	spool: &FsSpool,
	config: &Config,
	name: &str,
	queue: QueuePolicy,
	bayes_store: Option<&crate::antispam::corpus::BayesStore>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let result = runtime.block_on(remove_account(
		store,
		spool,
		&config.data_dir,
		name,
		queue,
		bayes_store,
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
			let _ = writeln!(
				out,
				"bayes corpus purge failed for {name}; account retained, retry the removal once the database is reachable"
			);
			super::style::error(error);
			ExitCode::FAILURE
		}
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}
