//! `mail accounts`: list the configured mail accounts from the command line.

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::AccountStore;

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
			eprintln!("error: opening account store: {error}");
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
