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

use clap::Subcommand as ClapSubcommand;

use crate::cli::style;
use crate::config::{Config, Protocol};
use crate::directory_store::{AccountStore, StoreError};

mod actions;
mod args;
mod class;
mod dispatch;
mod encryption_key;
mod forward_catch_all;
pub(super) mod json;
pub(super) mod list_aliases;
pub(super) mod name;
pub(super) mod reload;
mod switches;
mod two_factor;
#[allow(unused_imports)]
pub(super) use actions::{
	address_add_with_store, address_remove_with_store, disable_with_store, enable_with_store,
	find_log_id_with_store, handle_error, password_with_store, protocols_changed,
	protocols_with_store, quota_changed, quota_with_store, render, render_protocols,
	save_sent_with_store, set_name_with_store, show_with_store,
};
pub use args::{
	AddressArgs, AddressSubcommand, CatchAllArgs, CatchAllSubcommand, ForwardArgs,
	ForwardSubcommand, TwoFactorArgs, TwoFactorSubcommand,
};
use dispatch::{dispatch_catch_all, dispatch_forward, dispatch_two_factor};
#[allow(unused_imports)]
pub(super) use forward_catch_all::{
	catch_all_add_with_store, catch_all_list, catch_all_remove_with_store, forward_add_with_store,
	forward_list, forward_remove_with_store,
};
#[allow(unused_imports)]
pub(super) use two_factor::{two_factor_disable, two_factor_show};

/// Every action the `epistle account` umbrella command understands.
/// Each maps to a single handler below; `clap` deserialises the trailing
/// positional arguments into the right variant. The first line of each
/// `about` must stay under 80 characters so the umbrella's `--help`
/// block fits one terminal page; longer context moves to `long_about`.
#[derive(Debug, ClapSubcommand)]
pub enum Subcommand {
	/// List every account (static and dynamic) with its addresses and source.
	List {
		/// Print a JSON array of `{"name", "source", "addresses"}` objects.
		#[arg(long)]
		json: bool,
		/// Show under each account the address aliases that deliver to it.
		///
		/// A disabled alias is marked, not hidden. With `--json` each account
		/// gains an `aliases` array of `{"address", "enabled", "hidden"}`.
		#[arg(long)]
		aliases: bool,
	},
	/// Create a dynamic account.
	///
	/// Password is asked twice with echo off on a terminal, one line from stdin
	/// otherwise.
	Add {
		/// Account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// An email address for the account (repeatable).
		#[arg(long = "address", value_name = "ADDR", required = true)]
		addresses: Vec<String>,
		/// The person's name, shown as the sender name (any case and script).
		#[arg(long, value_name = "TEXT")]
		display_name: Option<String>,
	},
	/// Set the display name of a dynamic account; an empty one clears it.
	SetName {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// The person's name, kept as written.
		#[arg(value_name = "DISPLAY_NAME")]
		display_name: String,
	},
	/// Remove a dynamic account and everything it owns.
	///
	/// That is its mailbox, masked addresses, app passwords, suppression
	/// entries and, with `--queue discard`, its queued mail.
	Remove {
		/// Account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// What to do with queued outbound mail: `discard` (drop) or `drain`
		/// (leave it for delivery). Required.
		#[arg(long = "queue", value_name = "POLICY", value_parser = crate::cli::accounts::parse_queue_policy)]
		queue: crate::directory_store::removal::QueuePolicy,
		/// Skip the interactive confirmation. A non-interactive run without
		/// `--yes` is refused with exit code 2.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Change an account's password.
	///
	/// Update the password for an account: asked twice with echo off on a
	/// terminal, read from stdin (one line) otherwise. Hashes it with argon2id
	/// and derives a fresh SCRAM salt, exactly the way account-add does on a
	/// fresh account.
	Password {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
	},
	/// Disable an account.
	///
	/// Authentication rejects it identically to an unknown login while the
	/// mailbox stays on disk; re-enable with `account enable`.
	Disable {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
	},
	/// Re-enable a previously disabled account.
	Enable {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
	},
	/// Add or remove a delivery address for the account.
	Address(AddressArgs),
	/// Set the account's storage quota (500M, 10G, 1T or none).
	///
	/// Set the storage quota for the account (e.g. `500M`, `10G`, `1T`, or
	/// `none` for the server default).
	Quota {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// The quota size (accepts `K`, `M`, `G`, `T` suffixes and the
		/// literal `none` for the server default).
		#[arg(value_name = "SIZE")]
		size: String,
	},
	/// Restrict which protocols the account may sign in through.
	///
	/// Restrict which authentication protocols the account may sign in through.
	/// `all` clears the restriction.
	Protocols {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// The protocol allowlist, comma-separated
		/// (`imap,smtp,api,webdav`), or `all` to clear.
		#[arg(value_name = "LIST")]
		list: String,
	},
	/// Change account settings.
	///
	/// `--default-class` sets the class granted to the account's mail when
	/// neither the request nor the credential names one (`none` clears it).
	/// `--send` and `--receive` switch sending and receiving on or off, each
	/// independent of `account disable` and of `account protocols`; a switch
	/// left out keeps its state, and both are on by default.
	#[command(group(
		clap::ArgGroup::new("setting")
			.required(true)
			.multiple(true)
			.args(["default_class", "send", "receive"])
	))]
	Set {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// `transactional`, `marketing`, `personal`, or `none`.
		#[arg(
			long = "default-class",
			value_name = "CLASS",
			conflicts_with_all = ["send", "receive"]
		)]
		default_class: Option<String>,
		/// `on` or `off`: whether the account may send mail.
		#[arg(long, value_name = "STATE")]
		send: Option<String>,
		/// `on` or `off`: whether mail addressed to the account is accepted.
		#[arg(long, value_name = "STATE")]
		receive: Option<String>,
	},
	/// Set whether the server saves a Sent copy of every send.
	SaveSent {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// `on` or `off`. The default (no account setting) is "on";
		/// `off` is the opt-out.
		#[arg(value_name = "STATE")]
		state: String,
	},
	/// Print the public view of an account, never its secrets.
	///
	/// Print the public view of an account (addresses, disabled, quota,
	/// protocols, log id). Never secrets.
	Show {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// Print one JSON object instead of `key: value` lines.
		#[arg(long)]
		json: bool,
	},
	/// Map a log pseudonym back to the account it stands for.
	///
	/// Map a log pseudonym (`acct-` plus 12 hex characters) back to the account
	/// it stands for, using this server's pseudonym key.
	FindLogId {
		/// The pseudonym as it appears in the server log.
		#[arg(value_name = "LOG_ID")]
		log_id: String,
	},
	/// Inspect or remove the account's two-factor (TOTP) enrolment.
	#[command(name = "2fa", alias = "two-factor")]
	TwoFactor(TwoFactorArgs),
	/// Manage the addresses an account's mail is also sent to.
	///
	/// Manage per-account forward targets (extra addresses a delivered message
	/// is also sent to).
	Forward(ForwardArgs),
	/// Manage the domains whose unknown users reach this account.
	///
	/// Manage per-account catch-all domains (deliver unknown local users in a
	/// domain to this account).
	CatchAll(CatchAllArgs),
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
/// `Ok(None)` to clear the restriction. Implementation lives in
/// `actions`; the umbrella keeps only the re-export so
/// the Subcommand enum stays close to the call site.
pub(super) fn parse_protocol_list(raw: &str) -> Result<Option<Vec<Protocol>>, String> {
	actions::parse_protocol_list_inner(raw)
}

/// Parse the `on`/`off` switch the `save_sent` and quota
/// subcommands accept. The CLI keeps the accepted set narrow so a
/// typo never lands on disk: `on` and `off` are the only valid
/// spellings. Implementation lives in `actions`.
pub(super) fn parse_on_off(raw: &str) -> Result<bool, String> {
	actions::parse_on_off(raw)
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
	.map(|store| store.with_password_policy(crate::password::Policy::from_config(&config.auth)))
}

/// `handle_error` lives in `actions`; the umbrella module only
/// re-exports it so callers can write `account::handle_error`.
/// Common prelude every mutating action shares: [`prepare_show`], then
/// refuse a static account with the config-file hint. Returns the open
/// store, or has already printed the error and returns
/// `ExitCode::FAILURE` so the caller can early-return. Both refusals run
/// before anything is read from stdin, so nobody types a password for a
/// name that cannot take one.
pub(super) fn prepare(config_path: &Path, name: &str) -> Result<AccountStore, ExitCode> {
	let store = prepare_show(config_path, name)?;
	if store.is_static(name) {
		return Err(crate::cli::exit::policy(format_args!(
			"account {name}: edit the config file to change a static account"
		)));
	}
	Ok(store)
}

/// Load the config, open the store and refuse a name that is neither a
/// static nor a dynamic account with `no such account: <name>`. Static
/// accounts pass: `account show` reports their public view and changes
/// nothing.
pub(super) fn prepare_show(config_path: &Path, name: &str) -> Result<AccountStore, ExitCode> {
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
	if !store.account_known(name) {
		return Err(crate::cli::exit::refused(format_args!(
			"no such account: {name}"
		)));
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
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// `list`/`add`/`remove` route to the same handlers the flat
	// `accounts`/`account-add`/`account-remove` commands drive, so the two
	// parsers cannot drift. `list` only reads; `add` is the one action that
	// reads from stdin (a new password) and so re-opens its own prompt
	// reader, while `remove` decides the queue policy before it touches
	// anything.
	match subcommand {
		Subcommand::List {
			json: leaf,
			aliases,
		} => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			if leaf || json {
				return crate::cli::account::json::list(&config, aliases, out);
			}
			super::accounts::list_with(&config, aliases, out)
		}
		Subcommand::Add {
			name,
			addresses,
			display_name,
		} => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			super::accounts::add_with_display_name(
				&config,
				&name,
				addresses,
				display_name.as_deref(),
				super::prompt::stdin(),
				out,
				json,
			)
		}
		Subcommand::Remove { name, queue, yes } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			super::accounts::remove_reporting(&config, &name, queue, yes, out, json)
		}
		Subcommand::Password { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			password_with_store(&store, &name, super::prompt::stdin(), out, json)
		}
		Subcommand::SetName { name, display_name } => match prepare(config_path, &name) {
			Ok(store) => set_name_with_store(&store, &name, &display_name, out, json),
			Err(code) => code,
		},
		Subcommand::Disable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			disable_with_store(&store, &name, out, json)
		}
		Subcommand::Enable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			enable_with_store(&store, &name, out, json)
		}
		Subcommand::Address(args) => match args.action {
			AddressSubcommand::Add { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_add_with_store(&store, &name, &address, out, json)
			}
			AddressSubcommand::Remove { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_remove_with_store(&store, &name, &address, out, json)
			}
		},
		Subcommand::Quota { name, size } => {
			let parsed = match parse_quota_size(&size) {
				Ok(size) => size,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			quota_with_store(&store, &name, parsed, out, json)
		}
		Subcommand::Protocols { name, list } => {
			let parsed = match parse_protocol_list(&list) {
				Ok(list) => list,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			protocols_with_store(&store, &name, parsed, out, json)
		}
		Subcommand::Set {
			name,
			default_class: Some(class),
			..
		} => crate::cli::account::class::set(config_path, &name, &class, json, out),
		Subcommand::Set {
			name,
			send,
			receive,
			..
		} => {
			let send = match switches::parse(&name, "send", send.as_deref()) {
				Ok(send) => send,
				Err(code) => return code,
			};
			let receive = match switches::parse(&name, "receive", receive.as_deref()) {
				Ok(receive) => receive,
				Err(code) => return code,
			};
			match prepare(config_path, &name) {
				Ok(store) => switches::set(&store, &name, send, receive, out, json),
				Err(code) => code,
			}
		}
		Subcommand::SaveSent { name, state } => {
			let value = match parse_on_off(&state) {
				Ok(value) => value,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			save_sent_with_store(&store, &name, value, out, json)
		}
		Subcommand::Show { name, json: leaf } => {
			let store = match prepare_show(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			if let Err(code) = init_log_id(config_path) {
				return code;
			}
			let key = encryption_key::describe(config_path, &store, &name);
			if leaf || json {
				return encryption_key::show_json(&store, &name, &key, out);
			}
			let code = show_with_store(&store, &name, out);
			if code == ExitCode::SUCCESS {
				encryption_key::show_line(out, &key);
			}
			code
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
				Ok(store) => find_log_id_with_store(&store, &log_id, out, json),
				Err(error) => {
					style::error(format_args!("opening account store: {error}"));
					ExitCode::FAILURE
				}
			}
		}
		// `forward` and `catch-all` accept the same umbrella shape, with a
		// dynamic-only mutator behind each: the dispatcher refuses a
		// static account with the config-file hint before any mutator
		// runs, mirroring `account enable`/`disable`.
		Subcommand::Forward(args) => dispatch_forward(args, config_path, json, out),
		Subcommand::CatchAll(args) => dispatch_catch_all(args, config_path, json, out),
		Subcommand::TwoFactor(args) => dispatch_two_factor(args, config_path, json, out),
	}
}
