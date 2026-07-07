//! `epistle app-password`: create, list and revoke per-account app passwords
//! (secondary mail credentials for IMAP/SMTP).

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::{AppPassword, AppPasswordStore};

/// Generate a strong random secret, hash it (argon2id) and store it for
/// `account` under `label`. The plaintext secret is printed once and never
/// stored. `expires_at` is epoch seconds; `ip_cidr` a single CIDR allowlist.
pub(super) fn create(
	config: &Config,
	account: &str,
	label: &str,
	expires_at: Option<u64>,
	ip_cidr: Option<String>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let secret = match super::generate_secret() {
		Some(secret) => secret,
		None => {
			eprintln!("error: cannot gather randomness for the secret");
			return ExitCode::FAILURE;
		}
	};
	let hash = match crate::smtp::auth::hash_password(&secret) {
		Ok(hash) => hash,
		Err(error) => {
			eprintln!("error: cannot hash secret: {error}");
			return ExitCode::FAILURE;
		}
	};
	let mut store = match AppPasswordStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening app-password store: {error}");
			return ExitCode::FAILURE;
		}
	};
	let app = AppPassword {
		label: label.to_string(),
		hash,
		expires_at,
		ip_cidr,
	};
	match store.add(account, app) {
		Ok(()) => {
			let _ = writeln!(out, "created app password \"{label}\" for {account}");
			let _ = writeln!(out, "secret (shown once): {secret}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

/// List every account's app passwords (never the secret or hash).
pub(super) fn list(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	let store = match AppPasswordStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening app-password store: {error}");
			return ExitCode::FAILURE;
		}
	};
	for (account, label, expires_at, ip_cidr) in store.list() {
		let expiry = expires_at.map_or_else(|| "never".to_string(), |e| e.to_string());
		let cidr = ip_cidr.unwrap_or_else(|| "any".to_string());
		if writeln!(out, "{account}\t{label}\texpires={expiry}\tip={cidr}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

/// Revoke an account's app password by label.
pub(super) fn revoke(
	config: &Config,
	account: &str,
	label: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let mut store = match AppPasswordStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening app-password store: {error}");
			return ExitCode::FAILURE;
		}
	};
	match store.remove(account, label) {
		Ok(()) => {
			let _ = writeln!(out, "revoked app password \"{label}\" for {account}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "app_passwords_tests.rs"]
mod tests;
