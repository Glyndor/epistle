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
	/// With `--account`, list that sending account's per-account list
	/// instead of the global one.
	List {
		/// Restrict the list to this sending account.
		#[arg(long, value_name = "ACCOUNT")]
		account: Option<String>,
		/// Print a JSON array of `{"address", "account"}` objects.
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
		#[arg(long, value_name = "ACCOUNT")]
		account: Option<String>,
	},
	/// Resume delivering to an address.
	///
	/// Drops the suppression marker, from the global list or, with
	/// `--account`, from that sender's list.
	Remove {
		/// Recipient address to resume delivering to.
		address: String,
		/// Remove the per-account suppression for this sender only.
		#[arg(long, value_name = "ACCOUNT")]
		account: Option<String>,
	},
}

/// Add `address` to the suppression list (the global one, or `account`'s).
pub(super) fn add(
	config: &Config,
	address: &str,
	account: Option<&str>,
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
	let address = address.to_ascii_lowercase();
	let line = match account {
		Some(account) => {
			list.suppress_for(account, &address);
			format!("suppressed {address} for {account}")
		}
		None => {
			list.suppress(&address);
			format!("suppressed {address}")
		}
	};
	let _ = writeln!(out, "{line}");
	ExitCode::SUCCESS
}

/// Remove one address from the suppression list (the per-account
/// table when `account` is `Some`).
pub(super) fn remove(
	config: &Config,
	address: &str,
	account: Option<&str>,
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
			let _ = writeln!(out, "removed {address}");
			ExitCode::SUCCESS
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
		SuppressionCli::Add { address, account } => add(config, &address, account.as_deref(), out),
		SuppressionCli::Remove { address, account } => {
			remove(config, &address, account.as_deref(), out)
		}
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
		return remove(config, address, account, out);
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
	let addresses = match account {
		Some(account) => list.list_for(account),
		None => list.list(),
	};
	if json {
		let rows: Vec<_> = addresses
			.iter()
			.map(|address| serde_json::json!({ "address": address, "account": account }))
			.collect();
		return super::json_out::print(out, &serde_json::Value::Array(rows));
	}
	for address in addresses {
		if writeln!(out, "{address}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;
