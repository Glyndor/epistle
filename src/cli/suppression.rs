//! `mail suppression`: view or edit the outbound suppression list (addresses
//! that hard-bounced and are no longer delivered to).

use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Config;
use crate::queue::SuppressionList;

/// Actions on the outbound suppression list (`epistle suppression
/// list|add|remove`).
#[derive(Debug, Subcommand)]
pub enum SuppressionCli {
	/// Print every suppressed address, one per line.
	///
	/// A hard bounce also gives when it happened and the remote reply, tab
	/// separated after the address. With `--account`, list that sending
	/// account's per-account list instead of the global one.
	List {
		/// Restrict the list to this sending account.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account_name::parse)]
		account: Option<String>,
		/// Print a JSON array of `{"address", "account", "since", "reason"}`
		/// objects (`since` and `reason` are null when not recorded).
		#[arg(long)]
		json: bool,
	},
	/// Stop delivering to an address.
	///
	/// Mail queued for it is dropped without a bounce, as after a hard
	/// bounce.
	Add {
		/// Recipient address to suppress.
		address: String,
		/// Suppress it for this sending account only, not for everyone.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account_name::parse)]
		account: Option<String>,
		/// Print the result as one JSON object on stdout.
		#[arg(long)]
		json: bool,
	},
	/// Resume delivering to an address.
	///
	/// Drops the suppression marker, from the global list or, with
	/// `--account`, from that sender's list.
	Remove {
		/// Recipient address to resume delivering to.
		address: String,
		/// Remove the per-account suppression for this sender only.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account_name::parse)]
		account: Option<String>,
		/// Print the result as one JSON object on stdout.
		#[arg(long)]
		json: bool,
	},
}

impl SuppressionCli {
	/// The action to run for a command line whose `--json` came before the
	/// action, or with no action at all: `address_to_remove` and `account`
	/// are the older flat forms, which list or remove when no action is
	/// named.
	pub(super) fn with_json(
		action: Option<Self>,
		json: bool,
		address_to_remove: Option<String>,
		account: Option<String>,
	) -> Option<Self> {
		if !json {
			return action;
		}
		Some(match action {
			Some(SuppressionCli::List { account, .. }) => SuppressionCli::List {
				account,
				json: true,
			},
			Some(SuppressionCli::Add {
				address, account, ..
			}) => SuppressionCli::Add {
				address,
				account,
				json: true,
			},
			Some(SuppressionCli::Remove {
				address, account, ..
			}) => SuppressionCli::Remove {
				address,
				account,
				json: true,
			},
			None => match address_to_remove {
				Some(address) => SuppressionCli::Remove {
					address,
					account,
					json: true,
				},
				None => SuppressionCli::List {
					account,
					json: true,
				},
			},
		})
	}
}

/// Add `address` to the suppression list (the global one, or `account`'s).
pub(super) fn add(
	config: &Config,
	address: &str,
	account: Option<&str>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// Anything that is not a deliverable address would sit in the list
	// forever and match nothing, so refuse it up front.
	if let Err(why) = crate::util::address_reason::parse(address) {
		return super::exit::refused(format_args!("cannot suppress: {why}"));
	}
	let list = match SuppressionList::open(&config.data_dir) {
		Ok(list) => list,
		Err(error) => {
			super::style::error(format_args!("cannot open suppression list: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let address = crate::util::address::normalize(address);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0);
	const REASON: &str = "added by hand (epistle suppression add)";
	let line = match account {
		Some(account) => {
			list.suppress_for_because(account, &address, REASON, now);
			format!("suppressed {address} for {account}")
		}
		None => {
			list.suppress_because(&address, REASON, now);
			format!("suppressed {address}")
		}
	};
	let mut report = super::json_out::Report::new(out, json);
	report.line(line);
	let fields = serde_json::json!({ "address": address, "account": account });
	report.change("add", true, fields, None)
}

/// Remove one address from the suppression list (the per-account
/// table when `account` is `Some`).
pub(super) fn remove(
	config: &Config,
	address: &str,
	account: Option<&str>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let list = match SuppressionList::open(&config.data_dir) {
		Ok(list) => list,
		Err(error) => {
			super::style::error(format_args!("cannot open suppression list: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let result = match account {
		Some(account) => list.remove_for(account, address),
		None => list.remove(address),
	};
	match result {
		Ok(()) => {
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!("removed {address}"));
			let fields = serde_json::json!({ "address": address, "account": account });
			report.change("remove", true, fields, None)
		}
		Err(error) => {
			super::style::error(format_args!("cannot remove {address}: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// Run every suppression action. Each branch opens the list itself so
/// the dispatchers (resource form and the legacy `--remove` form)
/// share the same exit-code and error wording.
pub(super) fn run(
	config: &Config,
	action: SuppressionCli,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match action {
		SuppressionCli::List { account, json } => list(config, account.as_deref(), json, out),
		SuppressionCli::Add {
			address,
			account,
			json,
		} => add(config, &address, account.as_deref(), json, out),
		SuppressionCli::Remove {
			address,
			account,
			json,
		} => remove(config, &address, account.as_deref(), json, out),
	}
}

/// Compatibility shim for the legacy `epistle suppression` (no action)
/// and `epistle suppression --remove ADDR` forms. The flat forms stay
/// supported as hidden aliases, but the resource form is the entry
/// point the help text shows.
pub(super) fn run_legacy(
	config: &Config,
	address_to_remove: Option<&str>,
	account: Option<&str>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	if let Some(address) = address_to_remove {
		return remove(config, address, account, false, out);
	}
	list(config, account, false, out)
}

/// Print every suppressed address in `account`'s scope (global when
/// `account` is `None`), one per line or, with `json`, as an array.
fn list(
	config: &Config,
	account: Option<&str>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let list = match SuppressionList::open(&config.data_dir) {
		Ok(list) => list,
		Err(error) => {
			super::style::error(format_args!("cannot open suppression list: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let entries = match account {
		Some(account) => list.entries_for(account),
		None => list.entries(),
	};
	let since = |entry: &crate::queue::Suppressed| entry.since.map(crate::clock::rfc3339);
	if json {
		let rows: Vec<_> = entries
			.iter()
			.map(|entry| {
				serde_json::json!({
					"address": entry.address,
					"account": account,
					"since": since(entry),
					"reason": entry.reason,
				})
			})
			.collect();
		return super::json_out::print(out, &serde_json::Value::Array(rows));
	}
	// One address per line; when the date and the reason were recorded they
	// follow, tab separated, so `cut -f1` still yields the bare addresses.
	for entry in &entries {
		let line = match (since(entry), &entry.reason) {
			(Some(since), Some(reason)) => format!("{}\t{since}\t{reason}", entry.address),
			_ => entry.address.clone(),
		};
		if writeln!(out, "{line}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "suppression_tests_reason.rs"]
mod tests_reason;
