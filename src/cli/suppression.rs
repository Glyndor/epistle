//! `mail suppression`: view or edit the outbound suppression list (addresses
//! that hard-bounced and are no longer delivered to).

use std::process::ExitCode;

use crate::config::Config;
use crate::queue::SuppressionList;

/// List suppressed addresses, or remove `remove` if given.
pub(super) fn run(
	config: &Config,
	remove: Option<&str>,
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
		if let Err(error) = list.remove(address) {
			eprintln!("error: cannot remove {address}: {error}");
			return ExitCode::FAILURE;
		}
		let _ = writeln!(out, "removed {address}");
		return ExitCode::SUCCESS;
	}
	for address in list.list() {
		if writeln!(out, "{address}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;
