//! `epistle api-key`: list, create, revoke and rotate management API keys.

use std::process::ExitCode;

use crate::api::api_keys::Scope;
use crate::api::{ApiKey, ApiKeyStore};
use crate::config::Config;

/// What `api-key create` (and the flat `api-key-create`) asks for.
#[derive(Debug, Default)]
pub(super) struct NewKey {
	/// A label identifying the key (e.g. "ci").
	pub(super) label: String,
	/// Expiry as Unix epoch seconds.
	pub(super) expires_at: Option<u64>,
	/// Single-CIDR client-IP allowlist.
	pub(super) ip_cidr: Option<String>,
	/// Permissions granted (`read`, `write`, `send`, `scim`).
	pub(super) scopes: Vec<String>,
	/// Domains the key is confined to; empty reaches every domain.
	pub(super) domains: Vec<String>,
	/// The one account the key is bound to.
	pub(super) account: Option<String>,
}

/// Generate a strong random key, hash it (SHA-256) and store it under
/// `key.label`. The plaintext key is printed once and never stored. The CLI
/// requires at least one scope: an unscoped key would be admin-equivalent on
/// first leak, which is the problem the scope field exists to fix. With
/// `account`, the key is bound to that account (static or dynamic) and only
/// the account-scoped surface (JMAP and `/api/v1/send`) accepts it, so it
/// may hold `read`, `write` and `send` but never `scim`, an administrative
/// scope with no "own account" to act on.
pub(super) fn create(config: &Config, key: NewKey, out: &mut impl std::io::Write) -> ExitCode {
	let NewKey {
		label,
		expires_at,
		ip_cidr,
		scopes,
		domains,
		account,
	} = key;
	let (label, account) = (label.as_str(), account.as_deref());
	if scopes.is_empty() {
		return super::exit::refused(
			"--scope is required (repeat to grant more than one: read, write, send, scim)",
		);
	}
	if let Some(name) = account {
		match account_known(config, name) {
			Ok(true) => {}
			Ok(false) => {
				return super::exit::refused(format_args!("--account {name}: no such account"));
			}
			Err(code) => return code,
		}
		if scopes.iter().any(|scope| scope == "scim") {
			return super::exit::refused(
				"account-bound API keys cannot hold the scim scope (scim is administrative)",
			);
		}
	}
	let secret = match super::generate_secret() {
		Some(secret) => secret,
		None => {
			super::style::error("cannot gather randomness for the key");
			return ExitCode::FAILURE;
		}
	};
	let mut store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening API key store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let key = ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(&secret),
		expires_at,
		ip_cidr,
		scopes,
		domains,
		account: account.map(str::to_string),
	};
	match store.add(key) {
		Ok(()) => {
			let _ = writeln!(out, "created API key \"{label}\"");
			if let Some(name) = account {
				let _ = writeln!(out, "account-bound to {name}");
			}
			let _ = writeln!(out, "key (shown once): {secret}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			let code = super::exit::for_io_error(&error);
			super::style::error(error);
			code
		}
	}
}

/// Whether `name` is an account on this server, static or dynamic. The
/// API resolves an account-bound key to that account through the same
/// directory delivery and IMAP use, so either kind can hold one. A store
/// that cannot be opened is an operation failure, not an unknown name.
fn account_known(config: &Config, name: &str) -> Result<bool, ExitCode> {
	crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.account_known(name))
	.map_err(|error| {
		super::style::error(format_args!("opening account store: {error}"));
		ExitCode::FAILURE
	})
}

/// Replace the secret of an API key, keeping its scopes, domains, expiry and
/// CIDR. The new key is printed once; the old one stops authenticating when
/// the running server's file watcher picks the change up.
pub(super) fn rotate(config: &Config, label: &str, out: &mut impl std::io::Write) -> ExitCode {
	let Some(secret) = super::generate_secret() else {
		super::style::error("cannot gather randomness for the key");
		return ExitCode::FAILURE;
	};
	let mut store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening API key store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	match store.rotate(label, crate::api::api_keys::sha256_hash(&secret)) {
		Ok(()) => {
			let _ = writeln!(
				out,
				"rotated API key \"{label}\"; the old key stops working within seconds"
			);
			let _ = writeln!(out, "key (shown once): {secret}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			let code = super::exit::for_io_error(&error);
			super::style::error(error);
			code
		}
	}
}

/// `epistle api-key <action>`.
#[derive(Debug, clap::Subcommand)]
pub enum ApiKeyCli {
	/// List the management API keys (never the key or its hash).
	List {
		/// Print a JSON array of key objects instead of one line per key.
		#[arg(long)]
		json: bool,
	},
	/// Create an API key and print it once.
	///
	/// The plaintext key is never stored. With `--account`, the key is bound
	/// to that account and refused by every route except JMAP and
	/// `/api/v1/send`; it may hold `read`, `write` and `send`, never `scim`.
	Create {
		/// A label identifying this API key (e.g. "ci").
		#[arg(value_name = "LABEL")]
		label: String,
		/// Optional expiry as Unix epoch seconds.
		#[arg(long, value_name = "EPOCH")]
		expires_at: Option<u64>,
		/// Optional single-CIDR client-IP allowlist.
		#[arg(long, value_name = "CIDR")]
		ip_cidr: Option<String>,
		/// Permissions granted (repeat to grant more than one: `read`,
		/// `write`, `send`). `scim` is rejected for account-bound keys.
		#[arg(
			long = "scope",
			value_name = "SCOPE",
			value_parser = parse_scope,
		)]
		scopes: Vec<String>,
		/// Confine this key to a domain (repeat for more).
		#[arg(long = "domain", value_name = "DOMAIN")]
		domains: Vec<String>,
		/// Bind the key to one account (then it reaches only JMAP and
		/// `/api/v1/send`). An account-bound key has no domain-wide reach,
		/// so `--domain` cannot be combined with it.
		#[arg(long, value_name = "ACCOUNT", conflicts_with = "domains", value_parser = crate::cli::account_name::parse)]
		account: Option<String>,
	},
	/// Revoke an API key by label.
	///
	/// Asks for confirmation on a terminal; `--yes` skips it, and a run
	/// without a terminal and without `--yes` is refused with exit code 2.
	Revoke {
		/// The label of the API key to revoke.
		#[arg(value_name = "LABEL")]
		label: String,
		/// Skip the interactive confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Replace a key's secret and print the new one once.
	///
	/// Scopes, domains, expiry and CIDR stay as they are; the old secret is
	/// revoked in the same write.
	Rotate {
		/// The label of the API key to rotate.
		label: String,
	},
}

/// Run one `epistle api-key <action>`.
pub(super) fn run(config: &Config, action: ApiKeyCli, out: &mut impl std::io::Write) -> ExitCode {
	match action {
		ApiKeyCli::List { json } => list(config, json, out),
		ApiKeyCli::Create {
			label,
			expires_at,
			ip_cidr,
			scopes,
			domains,
			account,
		} => create(
			config,
			NewKey {
				label,
				expires_at,
				ip_cidr,
				scopes,
				domains,
				account,
			},
			out,
		),
		ApiKeyCli::Revoke { label, yes } => revoke(config, &label, yes, out),
		ApiKeyCli::Rotate { label } => rotate(config, &label, out),
	}
}

/// List the management API keys (never the key or its hash), one line per
/// key or, with `json`, as an array of objects.
pub(super) fn list(config: &Config, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	let store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening API key store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if json {
		let rows = store
			.list()
			.into_iter()
			.map(|row| {
				serde_json::json!({
					"label": row.label,
					"expires_at": row.expires_at,
					"ip_cidr": row.ip_cidr,
					"scopes": row.scopes,
					"domains": row.domains,
					"account": row.account,
				})
			})
			.collect();
		return super::json_out::print(out, &serde_json::Value::Array(rows));
	}
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
		let bound = row
			.account
			.map(|account| format!("\taccount={account}"))
			.unwrap_or_default();
		if writeln!(
			out,
			"{label}\texpires={expiry}\tip={cidr}\tscopes={scopes_repr}{bound}",
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

/// Revoke a management API key by label. Asks
/// `Revoke API key "<label>"? [y/N]` on a terminal; `yes` (`--yes` /
/// `-y`) skips it. Without `--yes` on a non-interactive stdin the
/// command refuses with exit code 2 and a message that names `--yes`.
pub(super) fn revoke(
	config: &Config,
	label: &str,
	yes: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let mut store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening API key store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let Some(key) = store.list().into_iter().find(|key| key.label == label) else {
		return super::exit::refused(format_args!("no such API key \"{label}\""));
	};
	let question = format!(
		"Revoke API key \"{label}\" (scopes: {})? [y/N]",
		key.scopes.join(", ")
	);
	if let Err(code) = super::prompt::confirm_destructive("api-key-revoke", &question, yes) {
		return code;
	}
	match store.remove(label) {
		Ok(()) => {
			let _ = writeln!(out, "revoked API key \"{label}\"");
			ExitCode::SUCCESS
		}
		Err(error) => {
			let code = super::exit::for_io_error(&error);
			super::style::error(error);
			code
		}
	}
}

#[cfg(test)]
#[path = "api_keys_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "api_keys_tests_rotate.rs"]
mod tests_rotate;
