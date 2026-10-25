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
	/// The class granted to mail sent with the key.
	pub(super) class: Option<crate::evidence::MailClass>,
}

/// Generate a strong random key, hash it (SHA-256) and store it under
/// `key.label`. The plaintext key is printed once and never stored. The CLI
/// requires at least one scope: an unscoped key would be admin-equivalent on
/// first leak, which is the problem the scope field exists to fix. With
/// `account`, the key is bound to that account (static or dynamic) and only
/// the account-scoped surface (JMAP and `/api/v1/send`) accepts it, so it
/// may hold `read`, `write` and `send` but never `scim`, an administrative
/// scope with no "own account" to act on.
pub(super) fn create(
	config: &Config,
	key: NewKey,
	json: bool,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> ExitCode {
	let NewKey {
		label,
		expires_at,
		ip_cidr,
		scopes,
		domains,
		account,
		class,
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
			return super::exit::policy(
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
	let fields = serde_json::json!({
		"label": label, "key": secret, "scopes": scopes, "domains": domains,
		"account": account, "expires_at": expires_at, "ip_cidr": ip_cidr,
	});
	let hash = crate::api::api_keys::sha256_hash(&secret);
	if let Some(class) = class {
		let binding = crate::evidence::bindings::api_key_key(&hash);
		if let Err(error) = crate::evidence::bindings::update(&config.data_dir, |bindings| {
			bindings.credentials.insert(binding, class);
		}) {
			super::style::error(format_args!("binding the class: {error}"));
			return ExitCode::FAILURE;
		}
	}
	// Read before the move into the key: the advisory names the network it
	// was pinned to.
	let pinned =
		super::client_address::cidr_advisory(&config.data_dir, ip_cidr.as_deref(), "this key");
	let key = ApiKey {
		label: label.to_string(),
		hash,
		expires_at,
		ip_cidr,
		scopes,
		domains,
		account: account.map(str::to_string),
	};
	match store.add(key) {
		Ok(()) => {
			// The advisory travels with the result: stderr for a human, and
			// the `warnings` array of the JSON result for a script. The exit
			// code stays SUCCESS; the key was created as asked.
			let warnings = pinned.into_iter().collect::<Vec<_>>();
			for warning in &warnings {
				super::style::warn_to(err, warning);
			}
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!("created API key \"{label}\""));
			if let Some(name) = account {
				report.line(format_args!("account-bound to {name}"));
			}
			report.line(format_args!("key (shown once): {secret}"));
			let mut object = crate::cli::json_out::change_object("create", true, fields, None);
			// Absent when there is nothing to say, the same way `reload` is:
			// the published result object keeps exactly the keys it had.
			if !warnings.is_empty() {
				object["warnings"] = serde_json::json!(warnings);
			}
			report.object(object)
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
pub(super) fn rotate(
	config: &Config,
	label: &str,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
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
	let hash = crate::api::api_keys::sha256_hash(&secret);
	// The class follows the key to its new secret: bound to the new digest
	// before the rotation, the old binding dropped after it.
	let old = store
		.hash_of(label)
		.map(|old| crate::evidence::bindings::api_key_key(&old));
	let new = crate::evidence::bindings::api_key_key(&hash);
	if let Some(old) = &old
		&& let Err(error) = crate::evidence::bindings::update(&config.data_dir, |bindings| {
			if let Some(class) = bindings.credentials.get(old).copied() {
				bindings.credentials.insert(new.clone(), class);
			}
		}) {
		super::style::error(format_args!("carrying the class over: {error}"));
		return ExitCode::FAILURE;
	}
	match store.rotate(label, hash) {
		Ok(()) => {
			if let Some(old) = &old
				&& let Err(error) =
					crate::evidence::bindings::update(&config.data_dir, |bindings| {
						bindings.credentials.remove(old);
					}) {
				super::style::error(format_args!("dropping the old class binding: {error}"));
			}
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!(
				"rotated API key \"{label}\"; the old key stops working within seconds"
			));
			report.line(format_args!("key (shown once): {secret}"));
			let fields = serde_json::json!({ "label": label, "key": secret });
			report.change("rotate", true, fields, None)
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
		/// Optional expiry: Unix epoch seconds, a date (`2027-01-31`, midnight
		/// UTC), an RFC 3339 instant or a duration from now such as `90d`.
		#[arg(
			long,
			value_name = "WHEN",
			value_parser = super::api_keys_expiry::parse_expires_at,
		)]
		expires_at: Option<u64>,
		/// Optional expiry as a duration from now: a number and a unit
		/// (`s`, `m`, `h`, `d`, `w`), for example `90d`. `m` is minutes; for
		/// months count in days.
		#[arg(
			long,
			value_name = "DURATION",
			conflicts_with = "expires_at",
			value_parser = super::api_keys_expiry::parse_expires_in,
		)]
		expires_in: Option<u64>,
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
		/// The class granted to mail `/api/v1/send` submits with this key
		/// when the request names none.
		#[arg(long, value_name = "CLASS", value_parser = crate::evidence::class::parse_arg)]
		class: Option<crate::evidence::MailClass>,
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
pub(super) fn run(
	config: &Config,
	action: ApiKeyCli,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match action {
		ApiKeyCli::List { json: leaf } => {
			let mut err = super::style::stderr();
			list(config, leaf || json, out, &mut err)
		}
		ApiKeyCli::Create {
			label,
			expires_at,
			expires_in,
			ip_cidr,
			scopes,
			domains,
			account,
			class,
		} => {
			let mut err = super::style::stderr();
			create(
				config,
				NewKey {
					label,
					expires_at: expires_at.or(expires_in),
					ip_cidr,
					scopes,
					domains,
					account,
					class,
				},
				json,
				out,
				&mut err,
			)
		}
		ApiKeyCli::Revoke { label, yes } => revoke(config, &label, yes, json, out),
		ApiKeyCli::Rotate { label } => rotate(config, &label, json, out),
	}
}

/// List the management API keys (never the key or its hash), one line per
/// key or, with `json`, as an array of objects.
pub(super) fn list(
	config: &Config,
	json: bool,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> ExitCode {
	let store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening API key store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	// Each key that carries an allowlist the network cannot decide gets its
	// own advisory on stderr, before the listing. The `--json` output is a
	// bare array whose object keys are fixed, so nothing goes there.
	if !json {
		for row in store.list() {
			let subject = format!("key \"{}\"", row.label);
			if let Some(warning) = super::client_address::cidr_advisory(
				&config.data_dir,
				row.ip_cidr.as_deref(),
				&subject,
			) {
				super::style::warn_to(err, warning);
			}
		}
	}
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
	let now = super::api_keys_expiry::now_secs();
	for row in store.list() {
		let expiry = row.expires_at.map_or_else(
			|| "never".to_string(),
			|expires| super::api_keys_expiry::describe(expires, now),
		);
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
	json: bool,
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
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!("revoked API key \"{label}\""));
			report.change("revoke", true, serde_json::json!({ "label": label }), None)
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

#[cfg(test)]
#[path = "api_keys_tests_cidr.rs"]
mod tests_cidr;

#[cfg(test)]
#[path = "api_keys_tests_expiry.rs"]
mod tests_expiry;
