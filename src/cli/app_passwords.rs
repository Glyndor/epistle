//! `epistle app-password`: create, list and revoke per-account app passwords
//! (secondary mail credentials for IMAP/SMTP).

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::{AccountStore, AppPassword, AppPasswordStore};

/// Generate a strong random secret, hash it (argon2id) and store it for
/// `account` under `label`. The plaintext secret is printed once and never
/// stored. `expires_at` is epoch seconds; `ip_cidr` a single CIDR allowlist.
///
/// Refuses unknown or static accounts: an app password created under a
/// name nobody owns is orphan data the next account with the same name
/// inherits, and static accounts are not addressable through the
/// mutable `AppPasswordStore`. The check opens the account store
/// (the same kind of check `epistle masked` performs) so the failure
/// surfaces before any persistence happens.
pub(super) fn create(
	config: &Config,
	account: &str,
	label: &str,
	expires_at: Option<u64>,
	ip_cidr: Option<String>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	if let Err(error) = ensure_known_dynamic_account(config, account) {
		super::style::error(error);
		return ExitCode::FAILURE;
	}
	let secret = match super::generate_secret() {
		Some(secret) => secret,
		None => {
			super::style::error("cannot gather randomness for the secret");
			return ExitCode::FAILURE;
		}
	};
	let hash = match crate::smtp::auth::hash_password(&secret) {
		Ok(hash) => hash,
		Err(error) => {
			super::style::error(format_args!("cannot hash secret: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let mut store = match AppPasswordStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening app-password store: {error}"));
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
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// Open the account store and refuse anything that is not a real
/// dynamic account. `AppPasswordStore::add` does not enforce this, so
/// a typo (or a hostile `epistle app-password-create` against a fresh
/// `data_dir`) would otherwise produce an orphan credential that a
/// later account with the same name inherits. Static accounts are
/// not dynamic, so we reject them too: `AppPasswordStore` would not
/// be able to attribute the credential to them anyway.
fn ensure_known_dynamic_account(config: &Config, account: &str) -> Result<(), String> {
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| format!("opening account store: {error}"))?;
	if store.is_static(account) {
		return Err(format!(
			"account {account} is a static account; edit mail.toml to manage its credentials"
		));
	}
	let Some(_) = first_address(&store, account) else {
		return Err(format!("no such account: {account}"));
	};
	Ok(())
}

/// The first address of `account` from the account store's view, or
/// `None` when no such account exists in either static or dynamic
/// tables. A static account was filtered out one line above, so a
/// `Some` here proves the account is dynamic.
fn first_address(store: &AccountStore, account: &str) -> Option<String> {
	store
		.account_views()
		.into_iter()
		.find(|(name, _, _)| name == account)
		.map(|(_, addresses, _)| addresses.into_iter().next().unwrap_or_default())
}

/// List every account's app passwords (never the secret or hash).
pub(super) fn list(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	let store = match AppPasswordStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening app-password store: {error}"));
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

/// Revoke an account's app password by label. Asks
/// `Revoke app password "<label>" for "<account>"? [y/N]` on a
/// terminal; `yes` (`--yes` / `-y`) skips it. Without `--yes` on a
/// non-interactive stdin the command refuses with exit code 2 and a
/// message that names `--yes`.
pub(super) fn revoke(
	config: &Config,
	account: &str,
	label: &str,
	yes: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let mut store = match AppPasswordStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening app-password store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let known = store
		.list()
		.iter()
		.any(|(owner, name, _, _)| owner.eq_ignore_ascii_case(account) && name == label);
	if !known {
		super::style::error(crate::directory_store::StoreError::NotFound(format!(
			"{}/{label}",
			account.to_ascii_lowercase()
		)));
		return ExitCode::FAILURE;
	}
	let question = format!("Revoke app password \"{label}\" for \"{account}\"? [y/N]");
	if let Err(code) = super::prompt::confirm_destructive("app-password-revoke", &question, yes) {
		return code;
	}
	match store.remove(account, label) {
		Ok(()) => {
			let _ = writeln!(out, "revoked app password \"{label}\" for {account}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "app_passwords_tests.rs"]
mod tests;
