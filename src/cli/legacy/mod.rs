//! The flat commands that predate `epistle <resource> <action>`.
//!
//! `accounts`, `account-add`, `account-remove`, `app-password-create`,
//! `app-passwords`, `app-password-revoke`, `api-key-create`, `api-keys` and
//! `api-key-revoke` keep parsing so existing scripts do not break, and each
//! reaches the same handler as its resource form. They are flattened into
//! [`super::Command`] and hidden from `--help`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

use super::account;
use super::api_keys::{self, ApiKeyCli};
use super::dispatch::with_config;
use crate::cli::app::{passwords as app_passwords, passwords::AppPasswordCli};
use crate::directory_store::removal::QueuePolicy;

/// Every flat command kept as a hidden alias of a resource action.
#[derive(Debug, Subcommand)]
pub enum Legacy {
	/// (Compatibility) List every account: use `account list` instead. Kept
	/// as a hidden alias so an existing script still parses, but the
	/// resource form is the supported entry point.
	#[command(hide = true)]
	Accounts {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
	},
	/// (Compatibility) Create an account: use `account add` instead.
	#[command(hide = true)]
	AccountAdd {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
		/// The account name.
		#[arg(long, value_name = "NAME")]
		name: String,
		/// An email address for the account (repeatable).
		#[arg(long = "address", value_name = "ADDR", required = true)]
		addresses: Vec<String>,
	},
	/// (Compatibility) Remove an account: use `account remove` instead.
	#[command(hide = true)]
	AccountRemove {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
		/// The account name.
		#[arg(long, value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// What to do with queued outbound mail from the account:
		/// `discard` (drop it) or `drain` (leave it for delivery).
		#[arg(long = "queue", value_name = "POLICY", value_parser = super::accounts::parse_queue_policy)]
		queue: QueuePolicy,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// (Compatibility) Create an app password: use `app-password create`
	/// instead. Kept as a hidden alias so a script still parses.
	#[command(hide = true)]
	AppPasswordCreate {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
		/// The account the app password belongs to.
		#[arg(long, value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		account: String,
		/// A label identifying this app password (e.g. "iphone").
		#[arg(long, value_name = "LABEL")]
		label: String,
		/// Optional expiry as Unix epoch seconds.
		#[arg(long, value_name = "EPOCH")]
		expires_at: Option<u64>,
		/// Optional single-CIDR client-IP allowlist (e.g. 203.0.113.0/24).
		#[arg(long, value_name = "CIDR")]
		ip_cidr: Option<String>,
		/// Optional `save_sent` override for the credential. The
		/// legacy command exposes the same knob the canonical
		/// `app-password create --save-sent` does, kept so a
		/// scripted creation stays on the same line.
		#[arg(long, value_name = "STATE")]
		save_sent: Option<String>,
	},
	/// (Compatibility) List app passwords: use `app-password list` instead.
	#[command(hide = true)]
	AppPasswords {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
	},
	/// (Compatibility) Revoke an app password: use `app-password revoke`
	/// instead.
	#[command(hide = true)]
	AppPasswordRevoke {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
		/// The account the app password belongs to.
		#[arg(long, value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		account: String,
		/// The label of the app password to revoke.
		#[arg(long, value_name = "LABEL")]
		label: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// (Compatibility) Create an API key: use `api-key create` instead.
	#[command(hide = true)]
	ApiKeyCreate {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
		/// A label identifying this API key (e.g. "ci").
		#[arg(long, value_name = "LABEL")]
		label: String,
		/// Optional expiry: epoch seconds, a date, an RFC 3339 instant or a
		/// duration from now such as `90d`.
		#[arg(
			long,
			value_name = "WHEN",
			value_parser = crate::cli::api_keys::expiry::parse_expires_at,
		)]
		expires_at: Option<u64>,
		/// Optional single-CIDR client-IP allowlist (e.g. 203.0.113.0/24).
		#[arg(long, value_name = "CIDR")]
		ip_cidr: Option<String>,
		/// Permissions granted to this key (repeat to grant more than one:
		/// `read`, `write`, `send`, `scim`). Required at least once: an
		/// unscoped key is admin-equivalent, which is exactly what the scopes
		/// field exists to prevent.
		#[arg(
			long = "scope",
			value_name = "SCOPE",
			value_parser = api_keys::parse_scope,
		)]
		scopes: Vec<String>,
		/// Confine this key to a domain (repeat for more). Omitted, the key
		/// reaches every configured domain, which is what every key did
		/// before this option existed.
		#[arg(long = "domain", value_name = "DOMAIN")]
		domains: Vec<String>,
		/// Bind the key to one dynamic account (`api-key` then reaches only
		/// JMAP and `/api/v1/send`). The `scim` scope is rejected for
		/// account-bound keys, since SCIM manages accounts from outside and
		/// there is no equivalent of "the key's own account".
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
	},
	/// (Compatibility) List API keys: use `api-key list` instead.
	#[command(hide = true)]
	ApiKeys {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
	},
	/// (Compatibility) Revoke an API key: use `api-key revoke` instead.
	#[command(hide = true)]
	ApiKeyRevoke {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
		config: PathBuf,
		/// Print the result as JSON on stdout, as the resource form does.
		#[arg(long)]
		json: bool,
		/// The label of the API key to revoke.
		#[arg(long, value_name = "LABEL")]
		label: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
}

/// The resource action a flat command stands for.
#[derive(Debug)]
pub(super) enum Resource {
	/// `epistle account <action>`.
	Account(account::Subcommand),
	/// `epistle app-password <action>`.
	AppPassword(AppPasswordCli),
	/// `epistle api-key <action>`.
	ApiKey(ApiKeyCli),
}

impl Legacy {
	/// Whether the command line asked for `--json`.
	fn json(&self) -> bool {
		match self {
			Legacy::Accounts { json, .. }
			| Legacy::AccountAdd { json, .. }
			| Legacy::AccountRemove { json, .. }
			| Legacy::AppPasswordCreate { json, .. }
			| Legacy::AppPasswords { json, .. }
			| Legacy::AppPasswordRevoke { json, .. }
			| Legacy::ApiKeyCreate { json, .. }
			| Legacy::ApiKeys { json, .. }
			| Legacy::ApiKeyRevoke { json, .. } => *json,
		}
	}

	/// The config path and the resource action this flat command is an
	/// alias of. Running that action is all the flat command does.
	pub(super) fn into_resource(self) -> (PathBuf, Resource) {
		match self {
			Legacy::Accounts { config, json } => (
				config,
				Resource::Account(account::Subcommand::List { json }),
			),
			Legacy::AccountAdd {
				config,
				json: _,
				name,
				addresses,
			} => (
				config,
				Resource::Account(account::Subcommand::Add {
					name,
					addresses,
					display_name: None,
				}),
			),
			Legacy::AccountRemove {
				config,
				json: _,
				name,
				queue,
				yes,
			} => (
				config,
				Resource::Account(account::Subcommand::Remove { name, queue, yes }),
			),
			Legacy::AppPasswordCreate {
				config,
				json: _,
				account,
				label,
				expires_at,
				ip_cidr,
				save_sent,
			} => (
				config,
				Resource::AppPassword(AppPasswordCli::Create {
					account,
					label,
					expires_at,
					ip_cidr,
					save_sent,
					class: None,
				}),
			),
			Legacy::AppPasswords { config, json } => (
				config,
				Resource::AppPassword(AppPasswordCli::List {
					account: None,
					json,
				}),
			),
			Legacy::AppPasswordRevoke {
				config,
				json: _,
				account,
				label,
				yes,
			} => (
				config,
				Resource::AppPassword(AppPasswordCli::Revoke {
					account,
					label,
					yes,
				}),
			),
			Legacy::ApiKeyCreate {
				config,
				json: _,
				label,
				expires_at,
				ip_cidr,
				scopes,
				domains,
				account,
			} => (
				config,
				Resource::ApiKey(ApiKeyCli::Create {
					label,
					expires_at,
					expires_in: None,
					ip_cidr,
					scopes,
					domains,
					account,
					class: None,
				}),
			),
			Legacy::ApiKeys { config, json } => {
				(config, Resource::ApiKey(ApiKeyCli::List { json }))
			}
			Legacy::ApiKeyRevoke {
				config,
				json: _,
				label,
				yes,
			} => (config, Resource::ApiKey(ApiKeyCli::Revoke { label, yes })),
		}
	}
}

/// Run a flat command through the handler its resource form uses.
pub(super) fn run(command: Legacy) -> ExitCode {
	let json = command.json();
	let (config, resource) = command.into_resource();
	let mut out = std::io::stdout().lock();
	match resource {
		Resource::Account(action) => {
			with_config(&config, |_| account::run(&config, action, json, &mut out))
		}
		Resource::AppPassword(action) => with_config(&config, |config| {
			app_passwords::run(config, action, json, &mut out)
		}),
		Resource::ApiKey(action) => with_config(&config, |config| {
			api_keys::run(config, action, json, &mut out)
		}),
	}
}

#[cfg(test)]
mod tests;
