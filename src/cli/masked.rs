//! `epistle masked`: list, mint, switch and delete an account's masked
//! addresses from the shell.
//!
//! Masked addresses live in `<data_dir>/masked.json`. The running server
//! watches that file and reloads it within a couple of seconds, so a change
//! made here applies without a restart. Every write goes through the same
//! `AccountStore` methods the API uses, so the per-account cap
//! (`masked_addresses_max`) and the label rules are the same in both places.

use std::io::Write;

use super::term::table::Table;
use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Config;
use crate::directory_store::{AccountStore, StoreError};

/// Masked-address actions.
#[derive(Debug, Subcommand)]
pub enum MaskedCli {
	/// List an account's masked addresses.
	List {
		/// Account that owns the addresses.
		#[arg(value_parser = crate::cli::account::name::parse)]
		account: String,
		/// Print a JSON array instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Mint a new masked address for an account.
	Add {
		/// Account that will receive the mail.
		#[arg(value_parser = crate::cli::account::name::parse)]
		account: String,
		/// Human-readable label; its slug starts the address.
		#[arg(long, default_value = "mask")]
		label: String,
		/// Domain for the address. Defaults to the domain of the account's
		/// first address.
		#[arg(long)]
		domain: Option<String>,
	},
	/// Delete a masked address.
	Remove {
		/// Account that owns the address.
		#[arg(value_parser = crate::cli::account::name::parse)]
		account: String,
		/// The masked address to delete.
		address: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Let a disabled masked address receive mail again.
	Enable {
		/// Account that owns the address.
		#[arg(value_parser = crate::cli::account::name::parse)]
		account: String,
		/// The masked address to enable.
		address: String,
	},
	/// Stop delivery to a masked address without deleting it.
	Disable {
		/// Account that owns the address.
		#[arg(value_parser = crate::cli::account::name::parse)]
		account: String,
		/// The masked address to disable.
		address: String,
	},
}

/// Run one masked-address action. Data goes to `out`, diagnostics to `err`.
/// `now` is the current epoch second, stored as the creation time.
pub(super) fn run(
	config: &Config,
	action: MaskedCli,
	json: bool,
	now: u64,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store.with_masked_max(config.masked_addresses_max),
		Err(error) => {
			super::style::error_to(err, format_args!("cannot open the account store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let account = match &action {
		MaskedCli::List { account, .. }
		| MaskedCli::Add { account, .. }
		| MaskedCli::Remove { account, .. }
		| MaskedCli::Enable { account, .. }
		| MaskedCli::Disable { account, .. } => account.clone(),
	};
	let account = account.as_str();
	// The store would happily mint a mask for a name nobody owns; the mail
	// would then resolve to an account that cannot log in. Refuse it here.
	let Some(first_address) = first_address(&store, account) else {
		super::style::error_to(err, format_args!("no such account: {account}"));
		return ExitCode::from(super::exit::REFUSED);
	};
	let result = match action {
		MaskedCli::List { json: leaf, .. } => return list(&store, account, leaf || json, out, err),
		MaskedCli::Add { label, domain, .. } => {
			let domain = match pick_domain(config, domain, &first_address) {
				Ok(domain) => domain,
				Err(message) => {
					super::style::error_to(err, message);
					return ExitCode::from(super::exit::REFUSED);
				}
			};
			store
				.add_masked(account, &label, &domain, now)
				.map(|entry| {
					let fields =
						serde_json::json!({ "address": entry.address, "label": entry.label });
					(entry.address, "add", fields)
				})
		}
		MaskedCli::Remove { address, yes, .. } => {
			// An address the account does not own goes straight to the
			// store, which refuses it; there is nothing to confirm.
			let owned = store
				.list_masked(account)
				.iter()
				.any(|masked| masked.address.eq_ignore_ascii_case(&address));
			let question = format!("Remove masked address \"{address}\" from \"{account}\"? [y/N]");
			if owned
				&& let Err(code) =
					super::prompt::confirm_destructive("masked remove", &question, yes)
			{
				return code;
			}
			let fields = serde_json::json!({ "address": address });
			store
				.remove_masked(account, &address)
				.map(|()| (format!("removed {address}"), "remove", fields))
		}
		MaskedCli::Enable { address, .. } => {
			store.set_masked_enabled(account, &address, true).map(|_| {
				let fields = serde_json::json!({ "address": address, "enabled": true });
				(format!("enabled {address}"), "enable", fields)
			})
		}
		MaskedCli::Disable { address, .. } => {
			store.set_masked_enabled(account, &address, false).map(|_| {
				let fields = serde_json::json!({ "address": address, "enabled": false });
				(format!("disabled {address}"), "disable", fields)
			})
		}
	};
	match result {
		Ok((line, verb, mut fields)) => {
			fields["account"] = account.into();
			let mut report = super::json_out::Report::new(out, json);
			report.line(line);
			report.change(verb, true, fields, None)
		}
		Err(error) => {
			super::style::error_to(err, describe(&error));
			super::exit::for_store_error(&error)
		}
	}
}

/// The first address of `account`, or `None` when no such account exists.
fn first_address(store: &AccountStore, account: &str) -> Option<String> {
	store
		.account_views()
		.into_iter()
		.find(|(name, _, _)| name == account)
		.map(|(_, addresses, _)| addresses.into_iter().next().unwrap_or_default())
}

/// The domain for a new mask: the explicit `--domain` (it must be one the
/// server serves, or the address would never receive mail), otherwise the
/// domain of the account's own first address, otherwise the first configured
/// domain.
fn pick_domain(
	config: &Config,
	explicit: Option<String>,
	first_address: &str,
) -> Result<String, String> {
	let enabled = |domain: String| -> Result<String, String> {
		if super::disabled_domain::domain_of(config, &format!("x@{domain}")).is_some() {
			return Err(super::disabled_domain::refusal(&domain));
		}
		Ok(domain)
	};
	if let Some(domain) = explicit {
		let domain = domain.to_ascii_lowercase();
		return if config
			.domains
			.iter()
			.any(|d| d.eq_ignore_ascii_case(&domain))
		{
			enabled(domain)
		} else {
			Err(format!("{domain} is not one of the configured domains"))
		};
	}
	first_address
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_string())
		.or_else(|| config.domains.first().cloned())
		.ok_or_else(|| "no domain is configured for masked addresses".to_string())
		.and_then(enabled)
}

/// Print an account's masks, as text lines or a JSON array.
fn list(
	store: &AccountStore,
	account: &str,
	json: bool,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let rows = store.list_masked(account);
	if json {
		return match serde_json::to_string(&rows) {
			Ok(text) => {
				let _ = writeln!(out, "{text}");
				ExitCode::SUCCESS
			}
			Err(error) => {
				super::style::error_to(err, format_args!("cannot encode the list: {error}"));
				ExitCode::FAILURE
			}
		};
	}
	if let Some(decor) = super::term::stdout(json) {
		let mut table = Table::new(&["ADDRESS", "LABEL", "STATE"]).state_col(2);
		for row in rows {
			let state = if row.enabled { "enabled" } else { "disabled" };
			table.push(vec![row.address, row.label, state.into()]);
		}
		return match table.write(decor, out) {
			Ok(()) => ExitCode::SUCCESS,
			Err(_) => ExitCode::FAILURE,
		};
	}
	for row in rows {
		let state = if row.enabled { "enabled" } else { "disabled" };
		if writeln!(out, "{}\t{}\t{state}", row.address, row.label).is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

/// Operator-facing text for a store failure.
fn describe(error: &StoreError) -> String {
	match error {
		StoreError::NotFound(_) => "no such masked address".to_string(),
		StoreError::LimitReached { max } => {
			format!("masked-address limit ({max}) reached for the account")
		}
		other => other.to_string(),
	}
}

#[cfg(test)]
#[path = "masked_tests.rs"]
mod tests;
