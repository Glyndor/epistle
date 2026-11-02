//! `epistle storage tenant-keys`: re-encrypt stored mail under the key of
//! each account's tenant, or back under the server key.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::json;

use crate::config::Config;
use crate::storage::rekey::{self, Direction, Hooks, Journal, journal};
use crate::storage::{KeyOwner, MessageCrypto};

#[cfg(test)]
mod tests;

/// Tenant key actions.
#[derive(Debug, Subcommand)]
pub enum TenantKeysCli {
	/// Re-encrypt stored mail under the key each account should use now.
	///
	/// Mail and blobs move to the tenant key or the server key; a run cut
	/// short continues where it stopped.
	Migrate {
		/// Re-encrypt everything back under the server key, in the format a
		/// release without tenant keys reads. Needs `tenant_keys = false`.
		#[arg(long)]
		rollback: bool,
	},
}

/// Run a tenant key action against the configuration at `path`.
pub(in crate::cli) fn run(
	path: &Path,
	action: TenantKeysCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> ExitCode {
	let config = match Config::load(path) {
		Ok(config) => config,
		Err(error) => return fail(status, error),
	};
	let crypto = match MessageCrypto::from_full_config(&config) {
		Ok(crypto) => crypto,
		Err(error) => return fail(status, error),
	};
	if let Err(error) = crate::cli::util::attach_config_accounts(&crypto, &config) {
		return fail(status, format!("cannot read the accounts: {error}"));
	}
	let TenantKeysCli::Migrate { rollback } = action;
	let direction = if rollback {
		Direction::Rollback
	} else {
		Direction::Forward
	};
	let options = Options {
		direction,
		dry_run,
		json,
		live: crate::directory_store::reload_status::server_is_live(
			&config.data_dir,
			std::time::SystemTime::now(),
		),
	};
	let code = migrate(
		&config.data_dir,
		&crypto,
		&options,
		&mut rekey::NoHooks,
		out,
		status,
	);
	if code != ExitCode::SUCCESS || options.dry_run {
		return code;
	}
	match reseal_totp(&config, &crypto) {
		Ok(0) => code,
		Ok(count) if options.json => code_after(count, status),
		Ok(count) => match writeln!(out, "TOTP secrets resealed under the server key: {count}") {
			Ok(()) => code,
			Err(_) => ExitCode::FAILURE,
		},
		Err(error) => fail(status, format!("cannot reseal TOTP secrets: {error}")),
	}
}

/// With `--json` the stdout object is already written; the TOTP count goes
/// to the status stream instead.
fn code_after(count: usize, status: &mut impl Write) -> ExitCode {
	let _ = writeln!(
		status,
		"TOTP secrets resealed under the server key: {count}"
	);
	ExitCode::SUCCESS
}

/// What a migrate run was asked to do, and whether the server is up.
pub(crate) struct Options {
	pub(crate) direction: Direction,
	pub(crate) dry_run: bool,
	pub(crate) json: bool,
	pub(crate) live: bool,
}

/// Whether any `[[tenant]]` key is loaded.
fn has_tenant_keys(crypto: &MessageCrypto) -> bool {
	crypto
		.key_listing()
		.iter()
		.any(|(owner, _)| matches!(owner, KeyOwner::Tenant(_)))
}

/// Reseal under the current server key every TOTP secret in
/// `accounts.toml` that only a retired key opens, so the retired key can
/// go. Returns how many were resealed.
fn reseal_totp(config: &Config, crypto: &MessageCrypto) -> std::io::Result<usize> {
	if !config.data_dir.join("accounts.toml").is_file() {
		return Ok(0);
	}
	crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.with_crypto(crypto.clone()))
	.and_then(|store| store.reseal_totp())
	.map_err(|error| std::io::Error::other(error.to_string()))
}

fn fail(status: &mut impl Write, error: impl std::fmt::Display) -> ExitCode {
	crate::cli::style::error_to(status, error);
	ExitCode::FAILURE
}

/// Why a run must not start, or `None`.
fn refusal(
	crypto: &MessageCrypto,
	options: &Options,
	unfinished: Option<&Journal>,
) -> Option<String> {
	if !crypto.has_key(&KeyOwner::Server) {
		return Some("no [storage] key is configured; there is nothing to re-encrypt with".into());
	}
	if let Some(journal) = unfinished
		&& journal.direction != options.direction
	{
		return Some(format!(
			"an unfinished {} run is recorded in {}; run it again to finish it first",
			journal.direction,
			journal::JOURNAL_FILE
		));
	}
	if options.dry_run {
		return None;
	}
	match options.direction {
		Direction::Forward if !crypto.tenant_writes() && has_tenant_keys(crypto) => Some(
			"set [storage] tenant_keys = true and restart first, or new mail keeps arriving under the server key".into(),
		),
		Direction::Rollback if crypto.tenant_writes() => Some(
			"set [storage] tenant_keys = false and restart first, or new mail keeps arriving under tenant keys".into(),
		),
		_ if options.live => Some(
			"the server is running; stop it (epistle stack down) before re-encrypting, so no message is expunged or written mid-run".into(),
		),
		_ => None,
	}
}

/// The migrate run itself, with its hooks injectable for tests.
pub(crate) fn migrate(
	data_dir: &Path,
	crypto: &MessageCrypto,
	options: &Options,
	hooks: &mut dyn Hooks,
	out: &mut impl Write,
	status: &mut impl Write,
) -> ExitCode {
	let unfinished = match journal::read(data_dir) {
		Ok(found) => found,
		Err(error) => return fail(status, error),
	};
	if let Some(reason) = refusal(crypto, options, unfinished.as_ref()) {
		return fail(status, reason);
	}
	let mut progress = unfinished.unwrap_or_else(|| Journal::new(options.direction));
	let accounts = match rekey::accounts(data_dir) {
		Ok(accounts) => accounts,
		Err(error) => return fail(status, error),
	};
	let mut rows = Vec::new();
	for account in accounts {
		if progress.done.contains(&account) {
			continue;
		}
		let target = rekey::target_for(crypto, &account, options.direction);
		let totals =
			match rekey::rekey_account(crypto, data_dir, &account, &target, options.dry_run, hooks)
			{
				Ok(totals) => totals,
				Err(error) => {
					return fail(
						status,
						format!(
							"{account}: {error}; the run stopped here and resumes when run again"
						),
					);
				}
			};
		if !options.dry_run {
			progress.done.push(account.clone());
			progress.rewritten += totals.rewritten;
			if let Err(error) = journal::write(data_dir, &progress) {
				return fail(status, error);
			}
		}
		rows.push((account, target, totals));
	}
	if !options.dry_run
		&& let Err(error) = journal::remove(data_dir)
	{
		return fail(status, error);
	}
	report(&rows, options, out)
}

fn report(
	rows: &[(String, KeyOwner, rekey::Totals)],
	options: &Options,
	out: &mut impl Write,
) -> ExitCode {
	let verb = if options.dry_run {
		"would rewrite"
	} else {
		"rewrote"
	};
	let written = if options.json {
		let accounts: Vec<_> = rows
			.iter()
			.map(|(account, target, totals)| {
				json!({
					"account": account,
					"target": target.to_string(),
					"rewritten": totals.rewritten,
					"already": totals.already,
					"plaintext": totals.plaintext,
				})
			})
			.collect();
		writeln!(
			out,
			"{}",
			json!({
				"direction": options.direction.to_string(),
				"dry_run": options.dry_run,
				"accounts": accounts,
			})
		)
	} else {
		rows.iter().try_for_each(|(account, target, totals)| {
			writeln!(
				out,
				"{account}: {verb} {} file(s) under {target}; {} already there, {} plaintext left as is",
				totals.rewritten, totals.already, totals.plaintext
			)
		})
	};
	match written {
		Ok(()) => ExitCode::SUCCESS,
		Err(_) => ExitCode::FAILURE,
	}
}
