//! `epistle api-key`: create, list and revoke management API keys.

use std::process::ExitCode;

use crate::api::{ApiKey, ApiKeyStore};
use crate::config::Config;

/// Generate a strong random key, hash it (SHA-256) and store it under `label`.
/// The plaintext key is printed once and never stored. `expires_at` is epoch
/// seconds; `ip_cidr` a single CIDR allowlist.
pub(super) fn create(
	config: &Config,
	label: &str,
	expires_at: Option<u64>,
	ip_cidr: Option<String>,
	out: &mut impl std::io::Write,
) -> ExitCode {
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
	for (label, expires_at, ip_cidr) in store.list() {
		let expiry = expires_at.map_or_else(|| "never".to_string(), |e| e.to_string());
		let cidr = ip_cidr.unwrap_or_else(|| "any".to_string());
		if writeln!(out, "{label}\texpires={expiry}\tip={cidr}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
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
