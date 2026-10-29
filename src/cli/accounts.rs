//! `mail accounts`: list the configured mail accounts from the command line.

use std::process::ExitCode;
use std::sync::Arc;

use super::term::table::Table;
use crate::cli::account::reload as account_reload;
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
	if let Some(decor) = super::term::stdout(false) {
		let mut table = Table::new(&["NAME", "STATE", "SOURCE", "ADDRESSES"]).state_col(1);
		for (name, addresses, dynamic) in &views {
			let disabled = store.dynamic(name).is_some_and(|account| account.disabled);
			table.push(vec![
				name.clone(),
				if disabled { "disabled" } else { "enabled" }.to_string(),
				if *dynamic { "dynamic" } else { "static" }.to_string(),
				addresses.join(","),
			]);
		}
		let _ = table.write(decor, out);
	} else {
		for (name, addresses, dynamic) in &views {
			let source = if *dynamic { "dynamic" } else { "static" };
			let _ = writeln!(out, "{name}\t{source}\t{}", addresses.join(","));
		}
	}
	let _ = writeln!(out, "{} accounts", views.len());
	ExitCode::SUCCESS
}

/// Create a dynamic account with `addresses`, reading the password from
/// `reader` and hashing it (argon2id + SCRAM). On a terminal the password
/// is typed twice with echo off; piped stdin gives one line. The policy
/// (length, breached list) is checked before anything is written.
#[cfg(test)]
pub(super) fn add(
	config: &Config,
	name: &str,
	addresses: Vec<String>,
	reader: impl std::io::BufRead,
) -> ExitCode {
	let mut out = std::io::sink();
	add_with_display_name(config, name, addresses, None, reader, &mut out, false)
}

/// [`add`] with an optional display name, checked before the password is
/// read so nobody types one for an account that cannot be created.
pub(super) fn add_with_display_name(
	config: &Config,
	name: &str,
	addresses: Vec<String>,
	display_name: Option<&str>,
	mut reader: impl std::io::BufRead,
	out: &mut dyn std::io::Write,
	json: bool,
) -> ExitCode {
	let name = &crate::cli::account::name::for_new_account(name);
	let display_name = match display_name.map(crate::directory_store::display_name::validate) {
		None => None,
		Some(Ok(stored)) => stored,
		Some(Err(why)) => return super::exit::refused(format_args!("account {name}: {why}")),
	};
	// Open the store and check the name and addresses before the
	// password prompt, so a typo in either does not cost the operator
	// typing the password twice first. The refusal is the one `add`
	// would print after the prompt: same message, same exit code.
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
	if let Err(error) = store.validate_for_add(name, &addresses) {
		let code = super::exit::for_store_error(&error);
		super::style::error(error);
		return code;
	}
	for address in &addresses {
		if let Some(warning) = super::disabled_domain::warning(config, address) {
			super::style::warn(warning);
		}
	}
	// let-else, not `match`: a match arm that returns is still an arm of the
	// expression whose value binds to `password`, and the taint analyser follows
	// that edge - rust/hard-coded-cryptographic-value reported the exit code in
	// the Err arm as a password reaching the hash. An else block has to diverge,
	// so no value can travel from it to the binding. `new_password` has already
	// printed why it refused (no input, mismatch, or the policy rule that failed).
	let Some(password) =
		super::prompt::new_password(&format!("Password for \"{name}\""), &mut reader)
	else {
		return ExitCode::from(super::exit::REFUSED);
	};
	let fields = serde_json::json!({
		"account": name, "addresses": addresses, "display_name": display_name,
	});
	let account = match DynamicAccount::with_password(
		name.to_string(),
		addresses.clone(),
		&password,
		&crate::password::Policy::from_config(&config.auth),
		config.auth.scram,
	) {
		Ok(account) => DynamicAccount {
			display_name,
			..account
		},
		Err(error) => {
			// Hashing or salt generation failed: an operation failure.
			super::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	match store.add(account) {
		Ok(()) => {
			let mut report = super::json_out::Report::new(out, json);
			report.line("account created");
			// The store released its lock on `accounts.toml` when `add`
			// returned, so the server's reload is free to run while
			// this waits for it.
			let waited = account_reload::wait(store.store_path(), &mut super::style::stderr());
			report.change("add", true, fields, Some(waited.into()))
		}
		Err(error) => {
			let code = super::exit::for_store_error(&error);
			super::style::error(error);
			code
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
///
/// On a terminal it asks before touching anything (see
/// [`removal_question`]); `yes` (`--yes` / `-y`) skips the question, and
/// without a terminal or `--yes` it refuses with exit code 2.
#[cfg(test)]
pub(super) fn remove(
	config: &Config,
	name: &str,
	queue: QueuePolicy,
	yes: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	remove_reporting(config, name, queue, yes, out, false)
}

/// [`remove`], printing the counts as one JSON object when `json` is set.
pub(super) fn remove_reporting(
	config: &Config,
	name: &str,
	queue: QueuePolicy,
	yes: bool,
	out: &mut impl std::io::Write,
	json: bool,
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
	if store.is_static(name) {
		return super::exit::policy(format_args!(
			"account {name}: edit the config file to change a static account"
		));
	}
	if store.dynamic(name).is_none() {
		return super::exit::refused(format_args!("no such account: {name}"));
	}
	let question = removal_question(config, &store, name, queue);
	if let Err(code) = super::prompt::confirm_destructive("account-remove", &question, yes) {
		return code;
	}
	let spool = match FsSpool::open_configured(&config.data_dir, config.storage.as_ref()) {
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
	let mut err = super::style::stderr();
	remove_with_bayes(
		&runtime,
		&store,
		&spool,
		config,
		name,
		queue,
		bayes_store.as_ref(),
		out,
		&mut err,
		json,
	)
}

/// The question `account-remove` asks: the account, and the counts that
/// are cheap to read before anything is touched (masked addresses and app
/// passwords), plus the queue policy when queued mail will be dropped.
fn removal_question(
	config: &Config,
	store: &AccountStore,
	name: &str,
	queue: QueuePolicy,
) -> String {
	let masked = store.list_masked(name).len();
	let app_passwords = crate::directory_store::AppPasswordStore::open(&config.data_dir)
		.map(|passwords| {
			passwords
				.list()
				.into_iter()
				.filter(|(account, _, _, _, _)| account == name)
				.count()
		})
		.unwrap_or(0);
	let queued = match queue {
		QueuePolicy::Discard => ", discarding its queued mail",
		QueuePolicy::Drain => "",
	};
	format!(
		"Remove account \"{name}\" and its mailbox ({masked} masked addresses, \
		 {app_passwords} app passwords){queued}? [y/N]"
	)
}

/// Inner removal helper that the tests drive directly with a
/// hand-built [`BayesStore`]. The public [`remove`] opens the store
/// from the configuration; tests bypass `open_bayes_store` to feed
/// in a deterministic pool without touching the operator's
/// `[database]` URL. The `err` sink is separate from `out` so
/// decoration (`error:`, `warning:`) reaches the operator's terminal
/// while `out` carries the count summary the rest of the CLI
/// promises; tests pass a `Vec` wrapped in `AutoStream` so both
/// streams are observable.
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
	err: &mut impl std::io::Write,
	json: bool,
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
			let removed = [
				("mailbox_files", counts.mailbox_files),
				("masked_addresses", u64::from(counts.masked_addresses)),
				("app_passwords", u64::from(counts.app_passwords)),
				(
					"suppressed_addresses",
					u64::from(counts.suppressed_addresses),
				),
				(
					"queued_messages_discarded",
					u64::from(counts.queued_messages_discarded),
				),
				(
					"queued_messages_left",
					u64::from(counts.queued_messages_left),
				),
				("bayes_tokens_removed", counts.bayes_tokens_removed),
			];
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!("removed account {name}"));
			for (key, count) in removed {
				report.line(format_args!("{key}: {count}"));
			}
			// `err` is stderr outside the tests, the same stream the
			// other account commands print the note on.
			let waited = account_reload::wait(store.store_path(), err);
			let removed: serde_json::Map<String, serde_json::Value> = removed
				.into_iter()
				.map(|(key, count)| (key.to_string(), count.into()))
				.collect();
			let fields = serde_json::json!({ "account": name, "removed": removed });
			report.change("remove", true, fields, Some(waited.into()))
		}
		Err(StoreError::NotFound(what)) => {
			super::style::error_to(err, format_args!("no such dynamic account: {what}"));
			ExitCode::from(super::exit::REFUSED)
		}
		Err(StoreError::Invalid(message)) => {
			super::style::error_to(err, message);
			ExitCode::from(super::exit::REFUSED)
		}
		Err(error @ StoreError::BayesPurge { .. }) => {
			super::style::warn_to(
				err,
				format_args!(
					"bayes corpus purge failed for {name}; account retained, retry the removal once the database is reachable"
				),
			);
			super::style::error_to(err, format_args!("{error}"));
			ExitCode::FAILURE
		}
		Err(error) => {
			super::style::error_to(err, error);
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "accounts_add_validation_tests.rs"]
mod accounts_add_validation_tests;
