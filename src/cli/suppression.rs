//! `mail suppression`: view or edit the outbound suppression list (addresses
//! that hard-bounced and are no longer delivered to).

use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Config;
use crate::queue::SuppressionList;

/// Actions beside the flat `epistle suppression [--remove ADDR]` form.
#[derive(Debug, Subcommand)]
pub enum SuppressionCli {
	/// Stop delivering to an address: mail queued for it is dropped without
	/// a bounce, as after a hard bounce.
	Add {
		/// Recipient address to suppress.
		address: String,
		/// Suppress it for this sending account only, not for everyone.
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
	if crate::smtp::address::Address::parse(address).is_err() {
		super::style::error(format_args!("{address:?} is not a valid email address"));
		return ExitCode::FAILURE;
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

/// List suppressed addresses, or remove `remove` if given. With `account`, the
/// operation targets that sending account's per-account list instead of the
/// global one.
pub(super) fn run(
	config: &Config,
	remove: Option<&str>,
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
	if let Some(address) = remove {
		let result = match account {
			Some(account) => list.remove_for(account, address),
			None => list.remove(address),
		};
		if let Err(error) = result {
			super::style::error(format_args!("cannot remove {address}: {error}"));
			return ExitCode::FAILURE;
		}
		let _ = writeln!(out, "removed {address}");
		return ExitCode::SUCCESS;
	}
	let addresses = match account {
		Some(account) => list.list_for(account),
		None => list.list(),
	};
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
