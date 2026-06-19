//! `mail accounts`: list the configured mail accounts from the command line.

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::{AccountStore, DynamicAccount};

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

/// Create a dynamic account with `addresses`, reading the password from
/// `reader` (one line) and hashing it (argon2id + SCRAM). `reader` is
/// injectable so the whole flow is testable.
pub(super) fn add(
	config: &Config,
	name: &str,
	addresses: Vec<String>,
	reader: impl std::io::BufRead,
) -> ExitCode {
	let password = match super::read_line(reader) {
		Ok(password) => password,
		Err(code) => return code,
	};
	let password_chars = password.chars().count();
	if !(12..=64).contains(&password_chars) {
		eprintln!("error: password must be between 12 and 64 characters");
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
			eprintln!("error: opening account store: {error}");
			return ExitCode::FAILURE;
		}
	};
	let account = match DynamicAccount::with_password(name.to_string(), addresses, &password) {
		Ok(account) => account,
		Err(error) => {
			eprintln!("error: {error}");
			return ExitCode::FAILURE;
		}
	};
	match store.add(account) {
		Ok(()) => {
			println!("created account {name}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}
