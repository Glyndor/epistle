//! `epistle api-key`: create, list and revoke management API keys.

use std::process::ExitCode;

use crate::api::api_keys::Scope;
use crate::api::{ApiKey, ApiKeyStore};
use crate::config::Config;

/// Generate a strong random key, hash it (SHA-256) and store it under `label`.
/// The plaintext key is printed once and never stored. `expires_at` is epoch
/// seconds; `ip_cidr` a single CIDR allowlist; `scopes` lists the permissions
/// granted (`read`, `write`, `send`, `scim`). The CLI requires at least one
/// scope — unscoped keys would be admin-equivalent on first leak, which is
/// the problem the scope field exists to fix.
pub(super) fn create(
	config: &Config,
	label: &str,
	expires_at: Option<u64>,
	ip_cidr: Option<String>,
	scopes: Vec<String>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	if scopes.is_empty() {
		eprintln!(
			"error: --scope is required (repeat to grant more than one: read, write, send, scim)"
		);
		return ExitCode::FAILURE;
	}
	let secret = match super::generate_secret() {
		Some(secret) => secret,
		None => {
			eprintln!("error: cannot gather randomness for the key");
			return ExitCode::FAILURE;
		}
	};
	let mut store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening API key store: {error}");
			return ExitCode::FAILURE;
		}
	};
	let key = ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(&secret),
		expires_at,
		ip_cidr,
		scopes,
	};
	match store.add(key) {
		Ok(()) => {
			let _ = writeln!(out, "created API key \"{label}\"");
			let _ = writeln!(out, "key (shown once): {secret}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

/// List the management API keys (never the key or its hash).
pub(super) fn list(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	let store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening API key store: {error}");
			return ExitCode::FAILURE;
		}
	};
	for row in store.list() {
		let expiry = row
			.expires_at
			.map_or_else(|| "never".to_string(), |e| e.to_string());
		let cidr = row.ip_cidr.unwrap_or_else(|| "any".to_string());
		// An empty scope list is a legacy key; show the warning verbatim so
		// operators can spot it on `api-key list` without grepping the logs.
		let scopes_repr = if row.scopes.is_empty() {
			"legacy(all)".to_string()
		} else {
			row.scopes.join(",")
		};
		if writeln!(
			out,
			"{label}\texpires={expiry}\tip={cidr}\tscopes={scopes_repr}",
			label = row.label,
		)
		.is_err()
		{
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

/// Validate a `--scope` argument. Called by the CLI dispatch before the value
/// reaches `ApiKeyStore::add` (the store repeats the check; this gives the
/// user a clean error before any I/O happens).
pub(super) fn parse_scope(value: &str) -> Result<String, String> {
	match value.parse::<Scope>() {
		Ok(_) => Ok(value.to_string()),
		Err(_) => Err(format!(
			"unknown scope \"{value}\" (expected read, write, send or scim)"
		)),
	}
}

/// Revoke a management API key by label.
pub(super) fn revoke(config: &Config, label: &str, out: &mut impl std::io::Write) -> ExitCode {
	let mut store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening API key store: {error}");
			return ExitCode::FAILURE;
		}
	};
	match store.remove(label) {
		Ok(()) => {
			let _ = writeln!(out, "revoked API key \"{label}\"");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "api_keys_tests.rs"]
mod tests;
