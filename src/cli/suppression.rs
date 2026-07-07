//! `mail suppression`: view or edit the outbound suppression list (addresses
//! that hard-bounced and are no longer delivered to).

use std::process::ExitCode;

use crate::config::Config;
use crate::queue::SuppressionList;

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
			eprintln!("error: cannot open suppression list: {error}");
			return ExitCode::FAILURE;
		}
	};
	if let Some(address) = remove {
		let result = match account {
			Some(account) => list.remove_for(account, address),
			None => list.remove(address),
		};
		if let Err(error) = result {
			eprintln!("error: cannot remove {address}: {error}");
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
