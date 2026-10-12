//! `epistle account …`: in-place mutators on a dynamic account that
//! would otherwise need an `accounts.toml` edit and a server reload.
//!
//! The action list is intentionally narrow: each subcommand maps to a
//! single `AccountStore` mutator, refuses a static account with a
//! message that tells the operator to edit the config file, and
//! returns `ExitCode::SUCCESS` only when the mutator reports success.
//! Anything beyond a thin wrapper here would belong on the store's
//! mutator, not on the CLI handler.
//!
//! The store lives in `<data_dir>/accounts.toml`; the running server
//! watches the file and rebuilds its directory within a few seconds,
//! so no service restart is needed. The watcher reload API is the same
//! one the sibling process drives from `add`, `remove` and
//! `set_password_hash`.

use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand as ClapSubcommand};

use crate::cli::style;
use crate::config::{Config, Protocol};
use crate::directory_store::{AccountStore, StoreError};

#[path = "account_actions.rs"]
mod account_actions;
#[allow(unused_imports)]
pub(super) use account_actions::{
	address_add_with_store, address_remove_with_store, disable_with_store, enable_with_store,
	find_log_id_with_store, handle_error, password_with_store, protocols_changed,
	protocols_with_store, quota_changed, quota_with_store, render, render_protocols,
	show_with_store,
};

/// Every action the `epistle account` umbrella command understands.
/// Each maps to a single handler below; `clap` deserialises the trailing
/// positional arguments into the right variant.
#[derive(Debug, ClapSubcommand)]
pub enum Subcommand {
	/// Update the password for an account, reading the new password from
	/// stdin (one line). Hashes it with argon2id and derives a fresh SCRAM
	/// salt, exactly the way `account-add` does on a fresh account.
	Password {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Disable an account. Authentication rejects it identically to an
	/// unknown login while the mailbox stays on disk; re-enable with
	/// `account enable`.
	Disable {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Re-enable a previously disabled account.
	Enable {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Add or remove a delivery address for the account.
	Address(AddressArgs),
	/// Set the storage quota for the account (e.g. `500M`, `10G`, `1T`,
	/// or `none` for the server default).
	Quota {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// The quota size (accepts `K`, `M`, `G`, `T` suffixes and the
		/// literal `none` for the server default).
		#[arg(value_name = "SIZE")]
		size: String,
	},
	/// Restrict which authentication protocols the account may sign in
	/// through. `all` clears the restriction.
	Protocols {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// The protocol allowlist, comma-separated
		/// (`imap,smtp,api,webdav`), or `all` to clear.
		#[arg(value_name = "LIST")]
		list: String,
	},
	/// Print the public view of an account (addresses, disabled, quota,
	/// protocols, log id). Never secrets.
	Show {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Map a log pseudonym (`acct-` plus 12 hex characters) back to the
	/// account it stands for, using this server's pseudonym key.
	FindLogId {
		/// The pseudonym as it appears in the server log.
		#[arg(value_name = "LOG_ID")]
		log_id: String,
	},
}

/// Sub-action on `epistle account address`.
#[derive(Debug, Args)]
pub struct AddressArgs {
	/// Add or remove the address.
	#[command(subcommand)]
	pub action: AddressSubcommand,
}

/// Add or remove a single address.
#[derive(Debug, ClapSubcommand)]
pub enum AddressSubcommand {
	/// Append the address to the account.
	Add {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// The address to add.
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
	/// Drop the address from the account (cannot remove the last one).
	Remove {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// The address to remove.
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
}

/// A byte suffix (K, M, G, T) parsed from the operator's quota string.
/// Stored as the multiplicative factor so the parser can be reused for
/// any case-sensitive unit without an extra lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaUnit {
	/// 2^10 bytes.
	K,
	/// 2^20 bytes.
	M,
	/// 2^30 bytes.
	G,
	/// 2^40 bytes.
	T,
}

impl QuotaUnit {
	fn factor(self) -> u64 {
		match self {
			QuotaUnit::K => 1024,
			QuotaUnit::M => 1024 * 1024,
			QuotaUnit::G => 1024 * 1024 * 1024,
			QuotaUnit::T => 1024 * 1024 * 1024 * 1024,
		}
	}
}

/// Parse a quota argument (`500M`, `10G`, `1T`, `none`) into bytes or
/// `None` for the server-default fallback. Rejects empty strings,
/// negative numbers and unknown suffixes so a typo never lands on disk.
pub(super) fn parse_quota_size(raw: &str) -> Result<Option<u64>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("quota size is empty (expected 500M, 10G, 1T or none)".to_string());
	}
	if trimmed.eq_ignore_ascii_case("none") {
		return Ok(None);
	}
	let split_at = trimmed
		.find(|c: char| !c.is_ascii_digit())
		.ok_or_else(|| format!("quota size {raw:?} needs a K/M/G/T suffix or 'none'"))?;
	let (number, suffix) = trimmed.split_at(split_at);
	if number.is_empty() {
		return Err(format!("quota size {raw:?} starts with a non-digit"));
	}
	let multiplier: u64 = number
		.parse()
		.map_err(|error| format!("quota size {raw:?}: {error}"))?;
	let unit_char = suffix
		.chars()
		.next()
		.ok_or_else(|| format!("quota size {raw:?} is missing a unit"))?;
	let unit = match unit_char {
		'K' | 'k' => QuotaUnit::K,
		'M' | 'm' => QuotaUnit::M,
		'G' | 'g' => QuotaUnit::G,
		'T' | 't' => QuotaUnit::T,
		other => {
			return Err(format!(
				"quota size {raw:?}: unknown unit {other:?} (expected K, M, G or T)"
			));
		}
	};
	if !suffix.chars().skip(1).all(|c| c.is_whitespace()) {
		return Err(format!(
			"quota size {raw:?}: trailing characters after unit"
		));
	}
	multiplier
		.checked_mul(unit.factor())
		.map(Some)
		.ok_or_else(|| format!("quota size {raw:?} overflows u64"))
}

/// Parse a protocol-list argument (`imap,smtp`, `all`). Unknown
/// protocol names are rejected with a list of the accepted ones so a
/// typo never reaches the store. `all` (case-insensitive) returns
/// `Ok(None)` to clear the restriction.
pub(super) fn parse_protocol_list(raw: &str) -> Result<Option<Vec<Protocol>>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("protocol list is empty (expected imap,smtp or 'all')".to_string());
	}
	if trimmed.eq_ignore_ascii_case("all") {
		return Ok(None);
	}
	let mut out = Vec::new();
	for token in trimmed.split(',') {
		let name = token.trim();
		if name.is_empty() {
			return Err("protocol list has an empty entry".to_string());
		}
		let protocol = parse_protocol(name)?;
		if !out.contains(&protocol) {
			out.push(protocol);
		}
	}
	Ok(Some(out))
}

/// Parse a single protocol name. Duplicates the kebab-case spellings
/// the TOML `Protocol` deserialiser already understands so the CLI
/// list and the config file spell them the same way.
fn parse_protocol(name: &str) -> Result<Protocol, String> {
	match name.to_ascii_lowercase().as_str() {
		"smtp" => Ok(Protocol::Smtp),
		"submission" => Ok(Protocol::Submission),
		"submissions" => Ok(Protocol::Submissions),
		"api" => Ok(Protocol::Api),
		"imap" => Ok(Protocol::Imap),
		"imaps" => Ok(Protocol::Imaps),
		"pop3s" => Ok(Protocol::Pop3s),
		"managesieve" => Ok(Protocol::ManageSieve),
		"webdav" => Ok(Protocol::WebDav),
		other => Err(format!(
			"unknown protocol {other:?} (expected smtp, submission, submissions, api, imap, imaps, pop3s, managesieve, webdav or 'all')"
		)),
	}
}

/// Open the store the action will mutate. Centralising the error
/// handling keeps the per-action branches focused on their mutator.
/// `[auth] scram` is applied here because `account password` derives (or,
/// with SCRAM off, drops) the verifier from the store's flag.
fn open_store(config: &Config) -> Result<AccountStore, StoreError> {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.with_scram_enabled(config.auth.scram))
}

/// `handle_error` lives in `account_actions`; the umbrella module only
/// re-exports it so callers can write `account::handle_error`.
/// Common prelude every action shares: load the config, open the
/// store, refuse static accounts. Returns the open store on success or
/// has already printed an error and returned `ExitCode::FAILURE` so
/// the caller can early-return.
pub(super) fn prepare(config_path: &Path, name: &str) -> Result<AccountStore, ExitCode> {
	let config = match Config::load(config_path) {
		Ok(config) => config,
		Err(error) => {
			style::error(error);
			return Err(ExitCode::FAILURE);
		}
	};
	let store = match open_store(&config) {
		Ok(store) => store,
		Err(error) => {
			style::error(format_args!("account {name}: {error}"));
			return Err(ExitCode::FAILURE);
		}
	};
	if store.is_static(name) {
		style::error(format_args!(
			"account {name}: edit the config file to change a static account"
		));
		return Err(ExitCode::FAILURE);
	}
	Ok(store)
}

/// Load the server's log pseudonym key so the pseudonyms this command
/// prints are the ones the running server writes to its log.
fn init_log_id(config_path: &Path) -> Result<(), ExitCode> {
	let config = Config::load(config_path).map_err(|error| {
		style::error(error);
		ExitCode::FAILURE
	})?;
	crate::log_id::init(&config.data_dir).map_err(|error| {
		style::error(format_args!("cannot open the log pseudonym key: {error}"));
		ExitCode::FAILURE
	})
}

/// Dispatch every `epistle account …` subcommand. The umbrella exists
/// so the operator can `tab-complete` from one root and so the
/// per-action handler signatures stay short.
pub(super) fn run(
	config_path: &Path,
	subcommand: Subcommand,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match subcommand {
		Subcommand::Password { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			password_with_store(&store, &name, std::io::stdin().lock())
		}
		Subcommand::Disable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			disable_with_store(&store, &name)
		}
		Subcommand::Enable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			enable_with_store(&store, &name)
		}
		Subcommand::Address(args) => match args.action {
			AddressSubcommand::Add { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_add_with_store(&store, &name, &address)
			}
			AddressSubcommand::Remove { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_remove_with_store(&store, &name, &address)
			}
		},
		Subcommand::Quota { name, size } => {
			let parsed = match parse_quota_size(&size) {
				Ok(size) => size,
				Err(error) => {
					style::error(format_args!("account {name}: {error}"));
					return ExitCode::FAILURE;
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			quota_with_store(&store, &name, parsed)
		}
		Subcommand::Protocols { name, list } => {
			let parsed = match parse_protocol_list(&list) {
				Ok(list) => list,
				Err(error) => {
					style::error(format_args!("account {name}: {error}"));
					return ExitCode::FAILURE;
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			protocols_with_store(&store, &name, parsed)
		}
		Subcommand::Show { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			if let Err(code) = init_log_id(config_path) {
				return code;
			}
			show_with_store(&store, &name, out)
		}
		Subcommand::FindLogId { log_id } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			if let Err(error) = crate::log_id::init(&config.data_dir) {
				style::error(format_args!("cannot open the log pseudonym key: {error}"));
				return ExitCode::FAILURE;
			}
			match open_store(&config) {
				Ok(store) => find_log_id_with_store(&store, &log_id, out),
				Err(error) => {
					style::error(format_args!("opening account store: {error}"));
					ExitCode::FAILURE
				}
			}
		}
	}
}
